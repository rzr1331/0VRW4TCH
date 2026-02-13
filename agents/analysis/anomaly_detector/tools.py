from __future__ import annotations

from .models import score_anomaly
from shared.tools.asset_discovery_tools import discover_runtime_assets
from shared.tools.monitoring_tools import fetch_metrics
from shared.tools.system_analyzer_tools import analyze_local_system


def detect_system_anomalies(
    query: str = "Detect monitoring and cybersecurity anomalies across running services.",
) -> dict:
    snapshot = analyze_local_system(query)
    discovered_assets = snapshot["discovered_assets"]
    metrics = snapshot["metrics"]
    analysis = snapshot["analysis"]
    anomaly_score = score_anomaly({"metrics": metrics, "findings": analysis.get("findings", [])})
    return {
        "query": query,
        "anomaly_score": anomaly_score,
        "discovered_assets": discovered_assets,
        "metrics": metrics,
        "analysis": analysis,
    }


TOOLS = [discover_runtime_assets, fetch_metrics, analyze_local_system, detect_system_anomalies]
