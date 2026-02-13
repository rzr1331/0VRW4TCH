from agents.perception.scope_scanner.sensors import collect_scope_targets
from shared.tools.asset_discovery_tools import discover_runtime_assets
from shared.tools.cloud_tools import fetch_cloud_inventory
from shared.tools.kubernetes_tools import get_cluster_health

TOOLS = [
    collect_scope_targets,
    discover_runtime_assets,
    fetch_cloud_inventory,
    get_cluster_health,
]
