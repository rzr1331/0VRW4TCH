from __future__ import annotations

from datetime import UTC, datetime
import socket
from typing import Any, Dict, List

from shared.tools.asset_discovery_tools import discover_runtime_assets
from shared.tools.cloud_tools import fetch_cloud_inventory
from shared.tools.kubernetes_tools import get_cluster_health


def _runtime_assets(discovery: Dict[str, Any], max_assets: int) -> List[Dict[str, Any]]:
    assets: List[Dict[str, Any]] = []
    host = discovery.get("host", {}) if isinstance(discovery, dict) else {}
    hostname = socket.gethostname()
    assets.append(
        {
            "asset_id": f"host-{hostname}",
            "asset_name": hostname,
            "asset_type": "critical",
            "asset_category": "infrastructure",
            "ip_address": "",
            "hostname": hostname,
            "operating_system": f"{host.get('platform', 'unknown')} {host.get('platform_release', '')}".strip(),
            "services": [],
            "owner": "platform",
            "business_criticality": "medium",
            "data_sensitivity": "internal",
            "dependencies": [],
            "upstream_dependencies": [],
            "tags": [str(discovery.get("runtime_profile", "unknown")), "host"],
            "last_scanned": datetime.now(UTC).isoformat(),
            "status": "active",
        }
    )

    for service in discovery.get("systemd", {}).get("running_services", [])[: max_assets // 3]:
        if not isinstance(service, dict):
            continue
        unit = str(service.get("unit", "unknown"))
        assets.append(
            {
                "asset_id": f"service-{unit}",
                "asset_name": unit,
                "asset_type": "important",
                "asset_category": "service",
                "ip_address": "",
                "hostname": hostname,
                "operating_system": "",
                "services": [unit],
                "owner": "ops",
                "business_criticality": "medium",
                "data_sensitivity": "internal",
                "dependencies": [],
                "upstream_dependencies": [],
                "tags": ["systemd", "runtime"],
                "last_scanned": datetime.now(UTC).isoformat(),
                "status": "active",
            }
        )

    for container in discovery.get("docker", {}).get("running_containers", [])[: max_assets // 3]:
        if not isinstance(container, dict):
            continue
        container_name = str(container.get("name", "container"))
        assets.append(
            {
                "asset_id": f"container-{container.get('id', container_name)}",
                "asset_name": container_name,
                "asset_type": "important",
                "asset_category": "container",
                "ip_address": "",
                "hostname": hostname,
                "operating_system": "",
                "services": [str(container.get("image", ""))],
                "owner": "platform",
                "business_criticality": "medium",
                "data_sensitivity": "internal",
                "dependencies": [],
                "upstream_dependencies": [],
                "tags": ["docker", "runtime"],
                "last_scanned": datetime.now(UTC).isoformat(),
                "status": "active",
            }
        )

    for listener in discovery.get("open_ports", {}).get("listeners", [])[: max_assets // 3]:
        if not isinstance(listener, dict):
            continue
        port = listener.get("port")
        if not isinstance(port, int):
            continue
        process = str(listener.get("process", "unknown"))
        assets.append(
            {
                "asset_id": f"port-{port}-{process}",
                "asset_name": f"{process}:{port}",
                "asset_type": "external",
                "asset_category": "network",
                "ip_address": str(listener.get("local_address", "")),
                "hostname": hostname,
                "operating_system": "",
                "services": [f"{listener.get('protocol', 'tcp')}:{port}"],
                "owner": "network",
                "business_criticality": "medium",
                "data_sensitivity": "internal",
                "dependencies": [],
                "upstream_dependencies": [],
                "tags": ["port", "listener"],
                "last_scanned": datetime.now(UTC).isoformat(),
                "status": "active",
            }
        )

    return assets[:max_assets]


def _cloud_assets(cloud_inventory: Dict[str, Any], max_assets: int) -> List[Dict[str, Any]]:
    assets: List[Dict[str, Any]] = []
    for cloud_asset in cloud_inventory.get("assets", [])[:max_assets]:
        if not isinstance(cloud_asset, dict):
            continue
        asset_name = str(cloud_asset.get("asset_name", cloud_asset.get("asset_id", "cloud-asset")))
        assets.append(
            {
                "asset_id": str(cloud_asset.get("asset_id", asset_name)),
                "asset_name": asset_name,
                "asset_type": "important",
                "asset_category": str(cloud_asset.get("asset_type", "cloud")),
                "ip_address": str(cloud_asset.get("ip_address", "")),
                "hostname": "",
                "operating_system": "",
                "services": [],
                "owner": str(cloud_asset.get("provider", "cloud")),
                "business_criticality": "medium",
                "data_sensitivity": "internal",
                "dependencies": [],
                "upstream_dependencies": [],
                "tags": [str(cloud_asset.get("provider", "cloud")), "cloud"],
                "last_scanned": datetime.now(UTC).isoformat(),
                "status": str(cloud_asset.get("status", "active")),
            }
        )
    return assets


def collect_scope_targets(max_processes: int = 200, max_assets: int = 500) -> Dict[str, Any]:
    """
    Build a consolidated asset inventory from runtime, Kubernetes, and cloud sources.
    Each source is optional; failures are recorded and do not stop the overall scan.
    """
    runtime_status = "ok"
    cloud_status = "ok"
    kubernetes_status = "ok"
    notes: List[str] = []

    runtime_data: Dict[str, Any] = {}
    cloud_data: Dict[str, Any] = {}
    cluster_data: Dict[str, Any] = {}

    try:
        runtime_data = discover_runtime_assets(max_processes=max_processes)
    except Exception as exc:
        runtime_status = "error"
        notes.append(f"runtime discovery failed: {exc}")

    try:
        cloud_data = fetch_cloud_inventory()
        unavailable = cloud_data.get("summary", {}).get("providers_unavailable", [])
        if unavailable:
            cloud_status = "partial"
            notes.append(f"cloud providers unavailable: {', '.join(unavailable)}")
    except Exception as exc:
        cloud_status = "error"
        notes.append(f"cloud inventory failed: {exc}")

    try:
        cluster_data = get_cluster_health()
        if cluster_data.get("status") in {"unknown", "degraded"}:
            kubernetes_status = "partial"
    except Exception as exc:
        kubernetes_status = "error"
        notes.append(f"kubernetes health discovery failed: {exc}")

    assets: List[Dict[str, Any]] = []
    if runtime_data:
        assets.extend(_runtime_assets(runtime_data, max_assets=max_assets))
    if cloud_data:
        assets.extend(_cloud_assets(cloud_data, max_assets=max_assets))
    if cluster_data:
        cluster_name = str(cluster_data.get("cluster", "unknown-cluster"))
        assets.append(
            {
                "asset_id": f"k8s-cluster-{cluster_name}",
                "asset_name": cluster_name,
                "asset_type": "critical",
                "asset_category": "kubernetes",
                "ip_address": "",
                "hostname": "",
                "operating_system": "",
                "services": [],
                "owner": "platform",
                "business_criticality": "high",
                "data_sensitivity": "internal",
                "dependencies": [],
                "upstream_dependencies": [],
                "tags": ["kubernetes", str(cluster_data.get("status", "unknown"))],
                "last_scanned": datetime.now(UTC).isoformat(),
                "status": "active" if cluster_data.get("status") == "ok" else "degraded",
            }
        )

    deduped_assets = list(
        {
            (
                str(asset.get("asset_id", "")),
                str(asset.get("asset_name", "")),
                str(asset.get("asset_category", "")),
            ): asset
            for asset in assets
        }.values()
    )[:max_assets]

    classification_counts = {
        "critical_assets": len([asset for asset in deduped_assets if asset.get("asset_type") == "critical"]),
        "important_assets": len([asset for asset in deduped_assets if asset.get("asset_type") == "important"]),
        "supporting_assets": len([asset for asset in deduped_assets if asset.get("asset_type") == "supporting"]),
        "external_assets": len([asset for asset in deduped_assets if asset.get("asset_type") == "external"]),
    }

    return {
        "assets": deduped_assets,
        "summary": {
            "total_assets": len(deduped_assets),
            **classification_counts,
            "scan_timestamp": datetime.now(UTC).isoformat(),
        },
        "sources": {
            "runtime": runtime_status,
            "cloud": cloud_status,
            "kubernetes": kubernetes_status,
        },
        "coverage": {
            "monitoring_targets": len(runtime_data.get("monitoring_targets", [])),
            "cloud_assets": len(cloud_data.get("assets", [])),
            "kubernetes_nodes_total": cluster_data.get("nodes", {}).get("total", 0) if cluster_data else 0,
        },
        "notes": notes[:20],
    }
