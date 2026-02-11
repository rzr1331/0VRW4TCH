from __future__ import annotations

from datetime import UTC, datetime
import json
import shutil
import subprocess
from typing import Any, Dict, List


def _run_command(
    command: List[str], timeout_seconds: int = 10
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


def _run_json_command(command: List[str], timeout_seconds: int = 10) -> tuple[Any, str | None]:
    result = _run_command(command, timeout_seconds=timeout_seconds)
    if result is None:
        return None, "command execution failed"
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        return None, message or f"command returned exit code {result.returncode}"
    try:
        return json.loads(result.stdout or "null"), None
    except json.JSONDecodeError:
        return None, "invalid json response"


def _aws_inventory(max_assets: int) -> Dict[str, Any]:
    if shutil.which("aws") is None:
        return {
            "provider": "aws",
            "status": "unavailable",
            "assets": [],
            "errors": ["aws CLI not installed"],
        }

    assets: List[Dict[str, Any]] = []
    errors: List[str] = []
    identity, identity_error = _run_json_command(
        ["aws", "sts", "get-caller-identity", "--output", "json"],
        timeout_seconds=8,
    )
    if identity_error:
        errors.append(f"sts identity failed: {identity_error}")
    elif isinstance(identity, dict):
        account_id = str(identity.get("Account", "unknown"))
        assets.append(
            {
                "asset_id": f"aws-account-{account_id}",
                "asset_name": f"AWS account {account_id}",
                "provider": "aws",
                "asset_type": "account",
                "status": "active",
            }
        )

    instances, instances_error = _run_json_command(
        ["aws", "ec2", "describe-instances", "--output", "json", "--max-items", str(max_assets)],
        timeout_seconds=15,
    )
    if instances_error:
        errors.append(f"ec2 inventory failed: {instances_error}")
    elif isinstance(instances, dict):
        reservations = instances.get("Reservations", [])
        if isinstance(reservations, list):
            for reservation in reservations:
                if not isinstance(reservation, dict):
                    continue
                for instance in reservation.get("Instances", [])[:max_assets]:
                    if not isinstance(instance, dict):
                        continue
                    instance_id = str(instance.get("InstanceId", "unknown"))
                    private_ip = str(instance.get("PrivateIpAddress", ""))
                    region = str(instance.get("Placement", {}).get("AvailabilityZone", "unknown"))[:-1]
                    assets.append(
                        {
                            "asset_id": instance_id,
                            "asset_name": instance_id,
                            "provider": "aws",
                            "asset_type": "compute",
                            "region": region or "unknown",
                            "ip_address": private_ip,
                            "status": str(instance.get("State", {}).get("Name", "unknown")),
                        }
                    )
                    if len(assets) >= max_assets:
                        break
                if len(assets) >= max_assets:
                    break

    status = "ok" if assets and not errors else "partial" if assets or errors else "unavailable"
    return {
        "provider": "aws",
        "status": status,
        "assets": assets[:max_assets],
        "errors": errors,
    }


def _gcp_inventory(max_assets: int) -> Dict[str, Any]:
    if shutil.which("gcloud") is None:
        return {
            "provider": "gcp",
            "status": "unavailable",
            "assets": [],
            "errors": ["gcloud CLI not installed"],
        }

    assets: List[Dict[str, Any]] = []
    errors: List[str] = []
    project_result = _run_command(
        ["gcloud", "config", "get-value", "project", "--quiet"],
        timeout_seconds=6,
    )
    project = ""
    if project_result is None or project_result.returncode != 0:
        errors.append("unable to resolve gcloud configured project")
    else:
        project = project_result.stdout.strip()
        if project and project != "(unset)":
            assets.append(
                {
                    "asset_id": f"gcp-project-{project}",
                    "asset_name": project,
                    "provider": "gcp",
                    "asset_type": "project",
                    "status": "active",
                }
            )

    instances, instances_error = _run_json_command(
        [
            "gcloud",
            "compute",
            "instances",
            "list",
            "--format=json",
            f"--limit={max_assets}",
            "--quiet",
        ],
        timeout_seconds=15,
    )
    if instances_error:
        errors.append(f"compute inventory failed: {instances_error}")
    elif isinstance(instances, list):
        for instance in instances[:max_assets]:
            if not isinstance(instance, dict):
                continue
            network_items = instance.get("networkInterfaces", [])
            network_ip = ""
            if isinstance(network_items, list) and network_items and isinstance(network_items[0], dict):
                network_ip = str(network_items[0].get("networkIP", ""))
            assets.append(
                {
                    "asset_id": str(instance.get("id", instance.get("name", "unknown"))),
                    "asset_name": str(instance.get("name", "unknown")),
                    "provider": "gcp",
                    "asset_type": "compute",
                    "region": str(instance.get("zone", "unknown")).split("/")[-1],
                    "ip_address": network_ip,
                    "status": str(instance.get("status", "unknown")).lower(),
                }
            )

    status = "ok" if assets and not errors else "partial" if assets or errors else "unavailable"
    return {
        "provider": "gcp",
        "status": status,
        "assets": assets[:max_assets],
        "errors": errors,
    }


def _azure_inventory(max_assets: int) -> Dict[str, Any]:
    if shutil.which("az") is None:
        return {
            "provider": "azure",
            "status": "unavailable",
            "assets": [],
            "errors": ["az CLI not installed"],
        }

    assets: List[Dict[str, Any]] = []
    errors: List[str] = []

    account, account_error = _run_json_command(
        ["az", "account", "show", "--output", "json"],
        timeout_seconds=8,
    )
    if account_error:
        errors.append(f"account lookup failed: {account_error}")
    elif isinstance(account, dict):
        subscription_id = str(account.get("id", "unknown"))
        assets.append(
            {
                "asset_id": f"azure-subscription-{subscription_id}",
                "asset_name": str(account.get("name", subscription_id)),
                "provider": "azure",
                "asset_type": "subscription",
                "status": str(account.get("state", "unknown")).lower(),
            }
        )

    vms, vm_error = _run_json_command(
        ["az", "vm", "list", "-d", "--output", "json"],
        timeout_seconds=20,
    )
    if vm_error:
        errors.append(f"vm inventory failed: {vm_error}")
    elif isinstance(vms, list):
        for vm in vms[:max_assets]:
            if not isinstance(vm, dict):
                continue
            assets.append(
                {
                    "asset_id": str(vm.get("id", vm.get("name", "unknown"))),
                    "asset_name": str(vm.get("name", "unknown")),
                    "provider": "azure",
                    "asset_type": "compute",
                    "region": str(vm.get("location", "unknown")),
                    "ip_address": str(vm.get("privateIps", "")),
                    "status": str(vm.get("powerState", "unknown")).lower(),
                }
            )

    status = "ok" if assets and not errors else "partial" if assets or errors else "unavailable"
    return {
        "provider": "azure",
        "status": status,
        "assets": assets[:max_assets],
        "errors": errors,
    }


def fetch_cloud_inventory(max_assets_per_provider: int = 50) -> Dict[str, Any]:
    """
    Best-effort cloud inventory using optional provider CLIs.
    Missing CLIs or auth do not raise errors; they are reported in results.
    """
    max_assets = max(1, min(max_assets_per_provider, 200))
    providers = [
        _aws_inventory(max_assets),
        _gcp_inventory(max_assets),
        _azure_inventory(max_assets),
    ]

    assets: List[Dict[str, Any]] = []
    errors: List[str] = []
    unavailable: List[str] = []
    for provider in providers:
        provider_name = str(provider.get("provider", "unknown"))
        assets.extend(provider.get("assets", []))
        for error in provider.get("errors", []):
            errors.append(f"{provider_name}: {error}")
        if provider.get("status") == "unavailable":
            unavailable.append(provider_name)

    return {
        "scanned_at": datetime.now(UTC).isoformat(),
        "assets": assets[: max_assets * 3],
        "providers": providers,
        "summary": {
            "total_assets": len(assets),
            "providers_checked": len(providers),
            "providers_unavailable": unavailable,
        },
        "errors": errors[:30],
        "note": "Cloud inventory is best-effort and depends on optional provider CLIs and credentials.",
    }
