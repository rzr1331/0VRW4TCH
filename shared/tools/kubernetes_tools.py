from __future__ import annotations

from datetime import UTC, datetime
import json
import shutil
import subprocess
from typing import Any, Dict


def _run_command(
    command: list[str], timeout_seconds: int = 8
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.SubprocessError, OSError):
        return None


def _run_json_command(command: list[str], timeout_seconds: int = 8) -> tuple[dict[str, Any] | None, str | None]:
    result = _run_command(command, timeout_seconds=timeout_seconds)
    if result is None:
        return None, "command execution failed"
    if result.returncode != 0:
        raw_message = (result.stderr or result.stdout or "").strip()
        lines = [line.strip() for line in raw_message.splitlines() if line.strip()]
        message = ""
        if lines:
            preferred = next(
                (
                    line
                    for line in reversed(lines)
                    if not line.startswith("E") and not line.startswith("W")
                ),
                lines[-1],
            )
            message = preferred[:280]
        return None, message or f"command returned exit code {result.returncode}"
    try:
        parsed = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return None, "invalid json response"
    if not isinstance(parsed, dict):
        return None, "json payload was not an object"
    return parsed, None


def get_cluster_health() -> Dict[str, Any]:
    checked_at = datetime.now(UTC).isoformat()
    kubectl_path = shutil.which("kubectl")
    if kubectl_path is None:
        return {
            "status": "unknown",
            "cluster": "unavailable",
            "checked_at": checked_at,
            "nodes": {"ready": 0, "total": 0},
            "control_plane": "unknown",
            "warnings": ["kubectl is not installed; Kubernetes health checks were skipped."],
        }

    warnings: list[str] = []
    cluster_name = "unknown"

    context_result = _run_command(["kubectl", "config", "current-context"], timeout_seconds=4)
    if context_result and context_result.returncode == 0 and context_result.stdout.strip():
        cluster_name = context_result.stdout.strip()
    else:
        warnings.append("Unable to determine kubectl current-context.")

    nodes_payload, nodes_error = _run_json_command(["kubectl", "get", "nodes", "-o", "json"], timeout_seconds=10)
    pods_payload, pods_error = _run_json_command(["kubectl", "get", "pods", "-A", "-o", "json"], timeout_seconds=12)
    deployments_payload, deployments_error = _run_json_command(
        ["kubectl", "get", "deployments", "-A", "-o", "json"],
        timeout_seconds=12,
    )

    if nodes_error:
        warnings.append(f"Node inventory unavailable: {nodes_error}")
    if pods_error:
        warnings.append(f"Pod inventory unavailable: {pods_error}")
    if deployments_error:
        warnings.append(f"Deployment inventory unavailable: {deployments_error}")

    total_nodes = 0
    ready_nodes = 0
    if nodes_payload:
        node_items = nodes_payload.get("items", [])
        if isinstance(node_items, list):
            total_nodes = len(node_items)
            for node in node_items:
                if not isinstance(node, dict):
                    continue
                conditions = node.get("status", {}).get("conditions", [])
                if not isinstance(conditions, list):
                    continue
                if any(
                    isinstance(condition, dict)
                    and condition.get("type") == "Ready"
                    and condition.get("status") == "True"
                    for condition in conditions
                ):
                    ready_nodes += 1

    total_pods = 0
    non_running_pods = 0
    namespaces: set[str] = set()
    if pods_payload:
        pod_items = pods_payload.get("items", [])
        if isinstance(pod_items, list):
            total_pods = len(pod_items)
            for pod in pod_items:
                if not isinstance(pod, dict):
                    continue
                metadata = pod.get("metadata", {})
                if isinstance(metadata, dict):
                    namespace = metadata.get("namespace")
                    if isinstance(namespace, str) and namespace:
                        namespaces.add(namespace)
                status = pod.get("status", {})
                phase = status.get("phase") if isinstance(status, dict) else None
                if phase and phase != "Running":
                    non_running_pods += 1

    unavailable_deployments = 0
    if deployments_payload:
        deployment_items = deployments_payload.get("items", [])
        if isinstance(deployment_items, list):
            for deployment in deployment_items:
                if not isinstance(deployment, dict):
                    continue
                status = deployment.get("status", {})
                unavailable = status.get("unavailableReplicas", 0) if isinstance(status, dict) else 0
                if isinstance(unavailable, int) and unavailable > 0:
                    unavailable_deployments += 1

    status = "ok"
    if total_nodes > 0 and ready_nodes < total_nodes:
        status = "degraded"
    if non_running_pods > 0 or unavailable_deployments > 0:
        status = "degraded"
    if total_nodes == 0 and nodes_error:
        status = "unknown"

    control_plane = "healthy" if status == "ok" else "degraded" if status == "degraded" else "unknown"
    return {
        "status": status,
        "cluster": cluster_name,
        "checked_at": checked_at,
        "nodes": {"ready": ready_nodes, "total": total_nodes},
        "control_plane": control_plane,
        "pods": {
            "total": total_pods,
            "non_running": non_running_pods,
            "namespaces_observed": len(namespaces),
        },
        "deployments": {"unavailable": unavailable_deployments},
        "warnings": warnings,
    }
