from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict


def get_cluster_health() -> Dict[str, Any]:
    # Local-development fallback until Kubernetes client integration is wired.
    return {
        "status": "ok",
        "cluster": "local-dev-cluster",
        "checked_at": datetime.now(UTC).isoformat(),
        "nodes": {"ready": 3, "total": 3},
        "control_plane": "healthy",
        "warnings": [
            "Mock telemetry in use. Wire Kubernetes API for live production data."
        ],
    }
