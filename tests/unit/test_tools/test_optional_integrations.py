from __future__ import annotations

from agents.analysis.vulnerability_assessor import tools as vuln_tools
from agents.perception.scope_scanner import sensors as scope_sensors
from shared.tools import cloud_tools, kubernetes_tools, security_tools


def test_security_scan_gracefully_handles_missing_tools(monkeypatch) -> None:
    monkeypatch.setattr(security_tools.shutil, "which", lambda _: None)

    result = security_tools.run_security_scan("localhost")

    assert result["target"] == "localhost"
    assert result["summary"]["total_findings"] == 0
    assert set(result["missing_tools"]) == {"falco", "nmap", "osqueryi", "trivy"}
    assert result["summary"]["tools_missing"] == 4


def test_kubernetes_health_handles_missing_kubectl(monkeypatch) -> None:
    monkeypatch.setattr(kubernetes_tools.shutil, "which", lambda _: None)

    result = kubernetes_tools.get_cluster_health()

    assert result["status"] == "unknown"
    assert result["nodes"]["total"] == 0
    assert any("kubectl is not installed" in warning for warning in result["warnings"])


def test_cloud_inventory_handles_missing_provider_clis(monkeypatch) -> None:
    monkeypatch.setattr(cloud_tools.shutil, "which", lambda _: None)

    result = cloud_tools.fetch_cloud_inventory()

    assert result["assets"] == []
    assert result["summary"]["providers_checked"] == 3
    assert set(result["summary"]["providers_unavailable"]) == {"aws", "azure", "gcp"}


def test_scope_scanner_continues_when_runtime_discovery_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        scope_sensors,
        "discover_runtime_assets",
        lambda max_processes=200: (_ for _ in ()).throw(RuntimeError("runtime missing")),
    )
    monkeypatch.setattr(
        scope_sensors,
        "fetch_cloud_inventory",
        lambda: {
            "assets": [
                {
                    "asset_id": "cloud-1",
                    "asset_name": "cloud-asset-1",
                    "asset_type": "compute",
                    "provider": "aws",
                    "status": "running",
                }
            ],
            "summary": {"providers_unavailable": []},
        },
    )
    monkeypatch.setattr(
        scope_sensors,
        "get_cluster_health",
        lambda: {
            "status": "ok",
            "cluster": "dev-cluster",
            "nodes": {"ready": 2, "total": 2},
            "warnings": [],
        },
    )

    result = scope_sensors.collect_scope_targets()

    assert result["sources"]["runtime"] == "error"
    assert result["sources"]["cloud"] == "ok"
    assert result["summary"]["total_assets"] >= 2
    assert any("runtime discovery failed" in note for note in result["notes"])


def test_vulnerability_sweep_uses_scope_targets(monkeypatch) -> None:
    monkeypatch.setattr(
        vuln_tools,
        "collect_scope_targets",
        lambda max_assets=400: {
            "assets": [
                {"ip_address": "10.0.0.7", "hostname": "api-1", "asset_name": "api-service"},
                {"ip_address": "", "hostname": "db-1", "asset_name": "database-service"},
            ],
            "summary": {"total_assets": 2},
        },
    )
    monkeypatch.setattr(
        vuln_tools,
        "run_security_scan",
        lambda target: {
            "target": target,
            "findings": [],
            "summary": {"total_findings": 0},
            "missing_tools": ["trivy"],
        },
    )

    result = vuln_tools.run_scope_security_sweep(max_targets=2)

    assert result["total_targets_scanned"] == 2
    assert result["targets_scanned"] == ["10.0.0.7", "db-1"]
    assert result["total_findings"] == 0
