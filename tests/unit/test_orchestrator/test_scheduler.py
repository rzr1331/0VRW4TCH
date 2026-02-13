from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from secops_platform.orchestrator import scheduler


def _scope_payload(asset_ids: list[str]) -> dict:
    return {
        "assets": [{"asset_id": asset_id} for asset_id in asset_ids],
        "summary": {"total_assets": len(asset_ids)},
    }


def _analysis_payload(
    finding_ids: list[str],
    ports: list[tuple[int, str, str]],
    *,
    risk: int = 0,
) -> dict:
    listeners = [
        {
            "port": port,
            "protocol": protocol,
            "local_address": address,
            "process": "svc",
        }
        for port, protocol, address in ports
    ]
    return {
        "discovered_assets": {"open_ports": {"listeners": listeners}},
        "analysis": {
            "findings": [{"id": finding_id} for finding_id in finding_ids],
            "risk_scores": {"overall_risk": risk},
        },
    }


def _vulnerability_payload(finding_ids: list[str]) -> dict:
    return {
        "scan_results": [
            {"target": "localhost", "findings": [{"id": finding_id} for finding_id in finding_ids]}
        ]
    }


def test_next_tick_rounds_to_next_boundary() -> None:
    aligned = datetime(2026, 2, 11, 10, 0, 0, tzinfo=UTC)
    unaligned = datetime(2026, 2, 11, 10, 1, 1, tzinfo=UTC)

    assert scheduler.next_tick(300, now=aligned) == datetime(2026, 2, 11, 10, 5, 0, tzinfo=UTC)
    assert scheduler.next_tick(300, now=unaligned) == datetime(2026, 2, 11, 10, 5, 0, tzinfo=UTC)


def test_snapshot_store_round_trip(tmp_path) -> None:
    store = scheduler.SnapshotStore(tmp_path / "history.db")

    snapshot_id = store.insert_snapshot(
        "scope",
        {"assets": [{"asset_id": "host-a"}]},
        captured_at="2026-02-11T10:00:00+00:00",
    )
    store.insert_snapshot(
        "cycle_summary",
        {"cycle": 1, "status": "ok"},
        captured_at="2026-02-11T10:00:00+00:00",
    )

    latest = store.latest_snapshot("scope")
    assert latest is not None
    assert latest["id"] == snapshot_id
    assert latest["payload"]["assets"][0]["asset_id"] == "host-a"

    summaries = store.recent_cycle_summaries(limit=5)
    assert len(summaries) == 1
    assert summaries[0]["payload"]["cycle"] == 1


def test_run_scan_cycle_persists_and_diffs_assets_ports_anomalies(monkeypatch, tmp_path) -> None:
    scope_payloads = [
        _scope_payload(["asset-a"]),
        _scope_payload(["asset-a", "asset-b"]),
    ]
    analysis_payloads = [
        _analysis_payload(["finding-a"], [(22, "tcp", "0.0.0.0:22")], risk=30),
        _analysis_payload(
            ["finding-a", "finding-b"],
            [(22, "tcp", "0.0.0.0:22"), (8080, "tcp", "0.0.0.0:8080")],
            risk=55,
        ),
    ]

    monkeypatch.setattr(scheduler, "collect_scope_targets", lambda: scope_payloads.pop(0))
    monkeypatch.setattr(
        scheduler,
        "analyze_local_system",
        lambda _: analysis_payloads.pop(0),
    )

    store = scheduler.SnapshotStore(tmp_path / "history.db")
    first = scheduler.run_scan_cycle(store)
    second = scheduler.run_scan_cycle(store)

    assert first["scope"]["total_assets"] == 1
    assert first["diff"]["assets"]["added_count"] == 1
    assert first["diff"]["open_ports"]["added_count"] == 1
    assert first["diff"]["anomalies"]["added_count"] == 1

    assert second["scope"]["total_assets"] == 2
    assert second["analysis"]["overall_risk"] == 55
    assert second["diff"]["assets"]["added_count"] == 1
    assert second["diff"]["assets"]["removed_count"] == 0
    assert second["diff"]["open_ports"]["added_count"] == 1
    assert second["diff"]["anomalies"]["added_count"] == 1

    recent = store.recent_cycle_summaries(limit=10)
    assert len(recent) == 2
    assert recent[0]["id"] == second["cycle_summary_id"]


def test_run_scan_cycle_tracks_vulnerability_diff_when_enabled(monkeypatch, tmp_path) -> None:
    scope_payload = _scope_payload(["asset-a"])
    analysis_payload = _analysis_payload(["finding-a"], [(22, "tcp", "0.0.0.0:22")], risk=10)
    vulnerability_payloads = [
        _vulnerability_payload(["cve-1"]),
        _vulnerability_payload(["cve-2"]),
    ]

    monkeypatch.setattr(scheduler, "collect_scope_targets", lambda: scope_payload)
    monkeypatch.setattr(scheduler, "analyze_local_system", lambda _: analysis_payload)
    monkeypatch.setattr(
        scheduler,
        "run_scope_security_sweep",
        lambda max_targets=8: vulnerability_payloads.pop(0),
    )

    store = scheduler.SnapshotStore(tmp_path / "history.db")
    first = scheduler.run_scan_cycle(store, enable_security_sweep=True, security_max_targets=3)
    second = scheduler.run_scan_cycle(store, enable_security_sweep=True, security_max_targets=3)

    assert first["vulnerability"]["enabled"] is True
    assert first["diff"]["vulnerabilities"]["added_count"] == 1
    assert second["diff"]["vulnerabilities"]["added_count"] == 1
    assert second["diff"]["vulnerabilities"]["removed_count"] == 1


def test_run_scheduler_executes_continuous_cycles_until_max(monkeypatch, tmp_path) -> None:
    store = scheduler.SnapshotStore(tmp_path / "history.db")
    cycle_calls: list[int] = []
    sleeps: list[float] = []

    def fake_run_scan_cycle(*args, **kwargs) -> dict:
        cycle_calls.append(1)
        return {
            "cycle_summary_id": len(cycle_calls),
            "scope": {"total_assets": 0},
            "analysis": {"overall_risk": 0, "anomaly_findings_total": 0},
        }

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(scheduler, "run_scan_cycle", fake_run_scan_cycle)
    monkeypatch.setattr(scheduler.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(
        scheduler,
        "next_tick",
        lambda interval_seconds, now=None: datetime.now(UTC),
    )

    asyncio.run(
        scheduler.run_scheduler(
            store=store,
            interval_seconds=60,
            max_cycles=3,
            enable_security_sweep=False,
        )
    )

    assert len(cycle_calls) == 3
    assert len(sleeps) == 2


def test_retention_policy_prunes_old_rows_while_keeping_recent_per_type(tmp_path) -> None:
    store = scheduler.SnapshotStore(tmp_path / "history.db")
    now = datetime.now(UTC)
    very_old = (now - timedelta(days=70)).isoformat()
    recent = (now - timedelta(days=1)).isoformat()

    store.insert_snapshot("scope", {"assets": [{"asset_id": "scope-old-1"}]}, captured_at=very_old)
    store.insert_snapshot("scope", {"assets": [{"asset_id": "scope-old-2"}]}, captured_at=very_old)
    store.insert_snapshot("scope", {"assets": [{"asset_id": "scope-new"}]}, captured_at=recent)
    store.insert_snapshot("analysis", {"analysis": {"findings": []}}, captured_at=very_old)

    result = store.apply_retention_policy(
        retention_days=30,
        keep_recent_per_type=1,
        compact=False,
    )

    assert result["deleted_count"] == 2
    assert result["compacted"] is False

    latest_scope = store.latest_snapshot("scope")
    latest_analysis = store.latest_snapshot("analysis")
    assert latest_scope is not None
    assert latest_analysis is not None
    assert latest_scope["payload"]["assets"][0]["asset_id"] == "scope-new"


def test_run_scheduler_applies_retention_and_compaction_cadence(monkeypatch, tmp_path) -> None:
    store = scheduler.SnapshotStore(tmp_path / "history.db")
    retention_calls: list[dict] = []

    def fake_run_scan_cycle(*args, **kwargs) -> dict:
        return {
            "cycle_summary_id": 1,
            "scope": {"total_assets": 0},
            "analysis": {"overall_risk": 0, "anomaly_findings_total": 0},
        }

    def fake_retention(*, retention_days: int, keep_recent_per_type: int, compact: bool) -> dict:
        retention_calls.append(
            {
                "retention_days": retention_days,
                "keep_recent_per_type": keep_recent_per_type,
                "compact": compact,
            }
        )
        return {
            "deleted_count": 0,
            "retention_days": retention_days,
            "keep_recent_per_type": keep_recent_per_type,
            "compacted": compact,
            "skipped_invalid_timestamp": 0,
        }

    async def fake_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(scheduler, "run_scan_cycle", fake_run_scan_cycle)
    monkeypatch.setattr(store, "apply_retention_policy", fake_retention)
    monkeypatch.setattr(scheduler.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(
        scheduler,
        "next_tick",
        lambda interval_seconds, now=None: datetime.now(UTC),
    )

    asyncio.run(
        scheduler.run_scheduler(
            store=store,
            interval_seconds=60,
            max_cycles=3,
            enable_security_sweep=False,
            retention_days=30,
            retention_keep_recent_per_type=2,
            compact_every_cycles=2,
        )
    )

    assert len(retention_calls) == 3
    assert [call["compact"] for call in retention_calls] == [False, True, False]
