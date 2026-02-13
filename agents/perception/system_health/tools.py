from shared.tools.asset_discovery_tools import discover_runtime_assets
from shared.tools.kubernetes_tools import get_cluster_health
from shared.tools.monitoring_tools import fetch_metrics
from shared.tools.system_analyzer_tools import analyze_local_system

TOOLS = [discover_runtime_assets, get_cluster_health, fetch_metrics, analyze_local_system]
