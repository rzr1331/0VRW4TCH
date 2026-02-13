from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any

from agents.analysis.vulnerability_assessor.tools import run_scope_security_sweep
from agents.perception.scope_scanner.sensors import collect_scope_targets
from shared.tools.system_analyzer_tools import analyze_local_system
from shared.utils.env import env_value
from shared.utils.logging import setup_logging

logger = logging.getLogger(__name__)
ROOT_DIR = Path(__file__).resolve().parents[2]


def _payload_json(payload: dict[str, Any], *, max_chars: int) -> str:
    encoded = json.dumps(payload, default=str, indent=2)
    if max_chars > 0 and len(encoded) > max_chars:
        return f"{encoded[:max_chars]}\n...<truncated>"
    return encoded


def _log_payload(
    *,
    cycle: int | str,
    step: str,
    payload: dict[str, Any],
    enabled: bool,
    max_chars: int,
) -> None:
    if not enabled:
        return
    logger.info(
        "scheduler_payload cycle=%s step=%s\n%s",
        cycle,
        step,
        _payload_json(payload, max_chars=max_chars),
    )


def _analysis_findings(analysis_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    analysis = analysis_snapshot.get("analysis", {})
    findings = analysis.get("findings", []) if isinstance(analysis, dict) else []
    if not isinstance(findings, list):
        return []
    return [finding for finding in findings if isinstance(finding, dict)]


def _vulnerability_findings(vulnerability_snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(vulnerability_snapshot, dict):
        return []
    scan_results = vulnerability_snapshot.get("scan_results", [])
    if not isinstance(scan_results, list):
        return []
    flattened: list[dict[str, Any]] = []
    for result in scan_results:
        if not isinstance(result, dict):
            continue
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if isinstance(finding, dict):
                flattened.append(finding)
    return flattened


def next_tick(interval_seconds: int, now: datetime | None = None) -> datetime:
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be > 0")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    epoch_seconds = int(current.timestamp())
    remainder = epoch_seconds % interval_seconds
    wait_seconds = interval_seconds if remainder == 0 else interval_seconds - remainder
    return current + timedelta(seconds=wait_seconds)


class SnapshotStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_type TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_snapshots_type_id "
                "ON scan_snapshots(snapshot_type, id)"
            )
            connection.commit()

    def insert_snapshot(
        self,
        snapshot_type: str,
        payload: dict[str, Any],
        *,
        captured_at: str | None = None,
    ) -> int:
        at = captured_at or datetime.now(UTC).isoformat()
        encoded = json.dumps(payload, default=str)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_snapshots(snapshot_type, captured_at, payload_json)
                VALUES(?, ?, ?)
                """,
                (snapshot_type, at, encoded),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def latest_snapshot(self, snapshot_type: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, captured_at, payload_json
                FROM scan_snapshots
                WHERE snapshot_type = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (snapshot_type,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        return {
            "id": int(row["id"]),
            "captured_at": str(row["captured_at"]),
            "payload": payload if isinstance(payload, dict) else {},
        }

    def recent_cycle_summaries(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 200))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, captured_at, payload_json
                FROM scan_snapshots
                WHERE snapshot_type = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                ("cycle_summary", safe_limit),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            results.append(
                {
                    "id": int(row["id"]),
                    "captured_at": str(row["captured_at"]),
                    "payload": payload if isinstance(payload, dict) else {},
                }
            )
        return results

    def apply_retention_policy(
        self,
        *,
        retention_days: int,
        keep_recent_per_type: int = 1,
        compact: bool = False,
    ) -> dict[str, Any]:
        if retention_days <= 0:
            raise ValueError("retention_days must be > 0")
        safe_keep_recent = max(0, keep_recent_per_type)
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, snapshot_type, captured_at
                FROM scan_snapshots
                ORDER BY snapshot_type ASC, id DESC
                """
            ).fetchall()

            protected_ids: set[int] = set()
            if safe_keep_recent > 0:
                seen: dict[str, int] = {}
                for row in rows:
                    snapshot_type = str(row["snapshot_type"])
                    count = seen.get(snapshot_type, 0)
                    if count >= safe_keep_recent:
                        continue
                    protected_ids.add(int(row["id"]))
                    seen[snapshot_type] = count + 1

            deletable_ids: list[int] = []
            skipped_invalid_timestamp = 0
            for row in rows:
                snapshot_id = int(row["id"])
                if snapshot_id in protected_ids:
                    continue

                captured_at = _safe_parse_datetime(str(row["captured_at"]))
                if captured_at is None:
                    skipped_invalid_timestamp += 1
                    continue

                if captured_at < cutoff:
                    deletable_ids.append(snapshot_id)

            deleted_count = 0
            if deletable_ids:
                placeholders = ",".join(["?"] * len(deletable_ids))
                cursor = connection.execute(
                    f"DELETE FROM scan_snapshots WHERE id IN ({placeholders})",
                    deletable_ids,
                )
                deleted_count = int(cursor.rowcount if cursor.rowcount != -1 else 0)
                connection.commit()

            compacted = False
            if compact and deleted_count > 0:
                connection.execute("VACUUM")
                compacted = True

        return {
            "deleted_count": deleted_count,
            "retention_days": retention_days,
            "keep_recent_per_type": safe_keep_recent,
            "compacted": compacted,
            "skipped_invalid_timestamp": skipped_invalid_timestamp,
        }


def _safe_parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _sorted_diff(previous: set[str], current: set[str]) -> dict[str, Any]:
    added = sorted(current - previous)
    removed = sorted(previous - current)
    return {
        "added": added,
        "removed": removed,
        "added_count": len(added),
        "removed_count": len(removed),
    }


def _asset_ids(scope_payload: dict[str, Any]) -> set[str]:
    assets = scope_payload.get("assets", [])
    if not isinstance(assets, list):
        return set()
    identifiers: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        asset_id = str(asset.get("asset_id", "")).strip()
        asset_name = str(asset.get("asset_name", "")).strip()
        if asset_id:
            identifiers.add(asset_id)
        elif asset_name:
            identifiers.add(asset_name)
    return identifiers


def _port_ids(analysis_payload: dict[str, Any]) -> set[str]:
    discovered = analysis_payload.get("discovered_assets", {})
    listeners = discovered.get("open_ports", {}).get("listeners", []) if isinstance(discovered, dict) else []
    if not isinstance(listeners, list):
        return set()

    identifiers: set[str] = set()
    for listener in listeners:
        if not isinstance(listener, dict):
            continue
        port = listener.get("port")
        if not isinstance(port, int):
            continue
        protocol = str(listener.get("protocol", "tcp"))
        address = str(listener.get("local_address", ""))
        process = str(listener.get("process", "unknown"))
        identifiers.add(f"{protocol}|{address}|{port}|{process}")
    return identifiers


def _anomaly_ids(analysis_payload: dict[str, Any]) -> set[str]:
    analysis = analysis_payload.get("analysis", {})
    findings = analysis.get("findings", []) if isinstance(analysis, dict) else []
    if not isinstance(findings, list):
        return set()
    identifiers: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("id", "")).strip()
        title = str(finding.get("title", "")).strip()
        if finding_id:
            identifiers.add(finding_id)
        elif title:
            identifiers.add(title)
    return identifiers


def _vulnerability_ids(vulnerability_payload: dict[str, Any]) -> set[str]:
    scan_results = vulnerability_payload.get("scan_results", [])
    if not isinstance(scan_results, list):
        return set()
    identifiers: set[str] = set()
    for result in scan_results:
        if not isinstance(result, dict):
            continue
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding_id = str(finding.get("id", "")).strip()
            title = str(finding.get("title", "")).strip()
            if finding_id:
                identifiers.add(finding_id)
            elif title:
                identifiers.add(title)
    return identifiers


def _build_cycle_summary(
    *,
    captured_at: str,
    scope_snapshot: dict[str, Any],
    analysis_snapshot: dict[str, Any],
    vulnerability_snapshot: dict[str, Any] | None,
    previous_scope: dict[str, Any] | None,
    previous_analysis: dict[str, Any] | None,
    previous_vulnerability: dict[str, Any] | None,
    snapshot_ids: dict[str, int],
) -> dict[str, Any]:
    current_assets = _asset_ids(scope_snapshot)
    previous_assets = _asset_ids(previous_scope or {})
    current_ports = _port_ids(analysis_snapshot)
    previous_ports = _port_ids(previous_analysis or {})
    current_anomalies = _anomaly_ids(analysis_snapshot)
    previous_anomalies = _anomaly_ids(previous_analysis or {})

    vulnerability_diff = {"added": [], "removed": [], "added_count": 0, "removed_count": 0}
    if vulnerability_snapshot is not None:
        current_vulns = _vulnerability_ids(vulnerability_snapshot)
        previous_vulns = _vulnerability_ids(previous_vulnerability or {})
        vulnerability_diff = _sorted_diff(previous_vulns, current_vulns)

    analysis = analysis_snapshot.get("analysis", {})
    risk_scores = analysis.get("risk_scores", {}) if isinstance(analysis, dict) else {}
    scope_summary = scope_snapshot.get("summary", {}) if isinstance(scope_snapshot, dict) else {}

    return {
        "captured_at": captured_at,
        "snapshot_ids": snapshot_ids,
        "scope": {
            "total_assets": int(scope_summary.get("total_assets", 0)),
        },
        "analysis": {
            "overall_risk": int(risk_scores.get("overall_risk", 0))
            if isinstance(risk_scores.get("overall_risk", 0), int)
            else 0,
            "anomaly_findings_total": len(current_anomalies),
            "open_port_count": len(current_ports),
        },
        "vulnerability": {
            "enabled": vulnerability_snapshot is not None,
            "finding_total": len(_vulnerability_ids(vulnerability_snapshot or {})),
        },
        "diff": {
            "assets": _sorted_diff(previous_assets, current_assets),
            "open_ports": _sorted_diff(previous_ports, current_ports),
            "anomalies": _sorted_diff(previous_anomalies, current_anomalies),
            "vulnerabilities": vulnerability_diff,
        },
    }


def run_scan_cycle(
    store: SnapshotStore,
    *,
    enable_security_sweep: bool = False,
    security_max_targets: int = 8,
    cycle_number: int | None = None,
    log_payloads: bool = True,
    log_payload_max_chars: int = 120_000,
) -> dict[str, Any]:
    cycle = cycle_number if cycle_number is not None else "-"
    captured_at = datetime.now(UTC).isoformat()
    logger.info("scheduler_step cycle=%s step=cycle_start captured_at=%s", cycle, captured_at)
    previous_scope_row = store.latest_snapshot("scope")
    previous_analysis_row = store.latest_snapshot("analysis")
    previous_vulnerability_row = store.latest_snapshot("vulnerability")
    logger.info(
        "scheduler_step cycle=%s step=load_previous scope=%s analysis=%s vulnerability=%s",
        cycle,
        "yes" if previous_scope_row else "no",
        "yes" if previous_analysis_row else "no",
        "yes" if previous_vulnerability_row else "no",
    )

    logger.info("scheduler_step cycle=%s step=scope_scan_start", cycle)
    try:
        scope_snapshot = collect_scope_targets()
    except Exception as exc:
        logger.exception("scheduler_step cycle=%s step=scope_scan_error error=%s", cycle, exc)
        scope_snapshot = {
            "assets": [],
            "summary": {"total_assets": 0, "scan_timestamp": captured_at},
            "sources": {"runtime": "error", "cloud": "error", "kubernetes": "error"},
            "notes": [f"scope scan failed: {exc}"],
        }
    logger.info(
        "scheduler_step cycle=%s step=scope_scan_complete total_assets=%s",
        cycle,
        scope_snapshot.get("summary", {}).get("total_assets", 0)
        if isinstance(scope_snapshot, dict)
        else 0,
    )
    _log_payload(
        cycle=cycle,
        step="scope_scan",
        payload=scope_snapshot if isinstance(scope_snapshot, dict) else {},
        enabled=log_payloads,
        max_chars=log_payload_max_chars,
    )

    logger.info("scheduler_step cycle=%s step=analysis_start", cycle)
    try:
        analysis_snapshot = analyze_local_system("scheduled system analysis")
    except Exception as exc:
        logger.exception("scheduler_step cycle=%s step=analysis_error error=%s", cycle, exc)
        analysis_snapshot = {
            "query": "scheduled system analysis",
            "discovered_assets": {"open_ports": {"listeners": []}},
            "metrics": {"source": "error", "series": []},
            "analysis": {
                "findings": [],
                "risk_scores": {"overall_risk": 0},
                "summary": {"total": 0},
                "notes": [f"analysis failed: {exc}"],
            },
        }
    findings = _analysis_findings(analysis_snapshot if isinstance(analysis_snapshot, dict) else {})
    overall_risk = (
        analysis_snapshot.get("analysis", {}).get("risk_scores", {}).get("overall_risk", 0)
        if isinstance(analysis_snapshot, dict)
        else 0
    )
    logger.info(
        "scheduler_step cycle=%s step=analysis_complete findings=%s overall_risk=%s",
        cycle,
        len(findings),
        overall_risk,
    )
    for finding in findings:
        logger.info(
            "scheduler_finding cycle=%s source=analysis id=%s severity=%s title=%s",
            cycle,
            str(finding.get("id", "")),
            str(finding.get("severity", "")),
            str(finding.get("title", "")),
        )
    _log_payload(
        cycle=cycle,
        step="analysis",
        payload=analysis_snapshot if isinstance(analysis_snapshot, dict) else {},
        enabled=log_payloads,
        max_chars=log_payload_max_chars,
    )

    vulnerability_snapshot: dict[str, Any] | None = None
    if enable_security_sweep:
        logger.info(
            "scheduler_step cycle=%s step=vulnerability_sweep_start max_targets=%s",
            cycle,
            security_max_targets,
        )
        try:
            vulnerability_snapshot = run_scope_security_sweep(max_targets=security_max_targets)
        except Exception as exc:
            logger.exception("scheduler_step cycle=%s step=vulnerability_sweep_error error=%s", cycle, exc)
            vulnerability_snapshot = {
                "scope_summary": {},
                "targets_scanned": [],
                "total_targets_scanned": 0,
                "total_findings": 0,
                "scan_results": [],
                "note": f"vulnerability sweep failed: {exc}",
            }
        vulnerability_findings = _vulnerability_findings(vulnerability_snapshot)
        logger.info(
            "scheduler_step cycle=%s step=vulnerability_sweep_complete findings=%s targets=%s",
            cycle,
            len(vulnerability_findings),
            vulnerability_snapshot.get("total_targets_scanned", 0)
            if isinstance(vulnerability_snapshot, dict)
            else 0,
        )
        for finding in vulnerability_findings:
            logger.info(
                "scheduler_finding cycle=%s source=vulnerability id=%s severity=%s title=%s",
                cycle,
                str(finding.get("id", "")),
                str(finding.get("severity", "")),
                str(finding.get("title", "")),
            )
        _log_payload(
            cycle=cycle,
            step="vulnerability_sweep",
            payload=vulnerability_snapshot if isinstance(vulnerability_snapshot, dict) else {},
            enabled=log_payloads,
            max_chars=log_payload_max_chars,
        )
    else:
        logger.info("scheduler_step cycle=%s step=vulnerability_sweep_skipped", cycle)

    snapshot_ids = {
        "scope": store.insert_snapshot("scope", scope_snapshot, captured_at=captured_at),
        "analysis": store.insert_snapshot("analysis", analysis_snapshot, captured_at=captured_at),
    }
    if vulnerability_snapshot is not None:
        snapshot_ids["vulnerability"] = store.insert_snapshot(
            "vulnerability",
            vulnerability_snapshot,
            captured_at=captured_at,
        )

    summary = _build_cycle_summary(
        captured_at=captured_at,
        scope_snapshot=scope_snapshot,
        analysis_snapshot=analysis_snapshot,
        vulnerability_snapshot=vulnerability_snapshot,
        previous_scope=previous_scope_row["payload"] if previous_scope_row else None,
        previous_analysis=previous_analysis_row["payload"] if previous_analysis_row else None,
        previous_vulnerability=previous_vulnerability_row["payload"] if previous_vulnerability_row else None,
        snapshot_ids=snapshot_ids,
    )
    cycle_id = store.insert_snapshot("cycle_summary", summary, captured_at=captured_at)
    summary["cycle_summary_id"] = cycle_id
    logger.info(
        "scheduler_step cycle=%s step=summary_complete cycle_summary_id=%s added_assets=%s added_ports=%s added_anomalies=%s added_vulnerabilities=%s",
        cycle,
        cycle_id,
        summary.get("diff", {}).get("assets", {}).get("added_count", 0),
        summary.get("diff", {}).get("open_ports", {}).get("added_count", 0),
        summary.get("diff", {}).get("anomalies", {}).get("added_count", 0),
        summary.get("diff", {}).get("vulnerabilities", {}).get("added_count", 0),
    )
    _log_payload(
        cycle=cycle,
        step="cycle_summary",
        payload=summary,
        enabled=log_payloads,
        max_chars=log_payload_max_chars,
    )
    return summary


def _bool_env(name: str, default: bool) -> bool:
    raw = env_value(name, "true" if default else "false") or ("true" if default else "false")
    return raw.lower() in {"1", "true", "yes", "on"}


async def run_scheduler(
    *,
    store: SnapshotStore,
    interval_seconds: int,
    max_cycles: int | None = None,
    enable_security_sweep: bool = False,
    security_max_targets: int = 8,
    retention_days: int | None = None,
    retention_keep_recent_per_type: int = 3,
    compact_every_cycles: int = 24,
    log_payloads: bool = True,
    log_payload_max_chars: int = 120_000,
) -> None:
    logger.info(
        "scheduler_start interval_seconds=%s max_cycles=%s enable_security_sweep=%s security_max_targets=%s retention_days=%s retention_keep_recent_per_type=%s compact_every_cycles=%s log_payloads=%s log_payload_max_chars=%s db=%s",
        interval_seconds,
        max_cycles,
        enable_security_sweep,
        security_max_targets,
        retention_days,
        retention_keep_recent_per_type,
        compact_every_cycles,
        log_payloads,
        log_payload_max_chars,
        store.db_path,
    )
    cycle = 0
    while max_cycles is None or cycle < max_cycles:
        cycle += 1
        cycle_start = datetime.now(UTC)
        summary = run_scan_cycle(
            store,
            enable_security_sweep=enable_security_sweep,
            security_max_targets=security_max_targets,
            cycle_number=cycle,
            log_payloads=log_payloads,
            log_payload_max_chars=log_payload_max_chars,
        )
        logger.info(
            "scheduler_cycle_complete cycle=%s cycle_summary_id=%s assets=%s overall_risk=%s anomalies=%s",
            cycle,
            summary.get("cycle_summary_id"),
            summary.get("scope", {}).get("total_assets"),
            summary.get("analysis", {}).get("overall_risk"),
            summary.get("analysis", {}).get("anomaly_findings_total"),
        )

        if retention_days is not None and retention_days > 0:
            should_compact = compact_every_cycles > 0 and cycle % compact_every_cycles == 0
            retention_result = store.apply_retention_policy(
                retention_days=retention_days,
                keep_recent_per_type=retention_keep_recent_per_type,
                compact=should_compact,
            )
            logger.info(
                "scheduler_retention cycle=%s deleted=%s compacted=%s retention_days=%s keep_recent=%s skipped_invalid_timestamp=%s",
                cycle,
                retention_result.get("deleted_count", 0),
                retention_result.get("compacted", False),
                retention_result.get("retention_days"),
                retention_result.get("keep_recent_per_type"),
                retention_result.get("skipped_invalid_timestamp", 0),
            )

        if max_cycles is not None and cycle >= max_cycles:
            break

        target_tick = next_tick(interval_seconds, now=cycle_start)
        sleep_for = max(0.0, (target_tick - datetime.now(UTC)).total_seconds())
        await asyncio.sleep(sleep_for)


async def main() -> None:
    interval_seconds = int(env_value("SCHEDULER_INTERVAL_SECONDS", "300") or "300")
    max_cycles_raw = env_value("SCHEDULER_MAX_CYCLES")
    max_cycles = int(max_cycles_raw) if max_cycles_raw else None
    db_path_raw = env_value("SCHEDULER_DB_PATH", "./data/scan_history.db") or "./data/scan_history.db"
    db_path = Path(db_path_raw)
    if not db_path.is_absolute():
        db_path = ROOT_DIR / db_path

    enable_security_sweep = _bool_env("SCHEDULER_ENABLE_SECURITY_SWEEP", False)
    security_max_targets = int(
        env_value("SCHEDULER_SECURITY_MAX_TARGETS", "8") or "8"
    )
    retention_days = int(env_value("SCHEDULER_RETENTION_DAYS", "30") or "30")
    retention_keep_recent_per_type = int(
        env_value("SCHEDULER_RETENTION_KEEP_RECENT_PER_TYPE", "3") or "3"
    )
    compact_every_cycles = int(
        env_value("SCHEDULER_COMPACT_EVERY_CYCLES", "24") or "24"
    )
    log_payloads = _bool_env("SCHEDULER_LOG_PAYLOADS", True)
    log_payload_max_chars = int(
        env_value("SCHEDULER_LOG_PAYLOAD_MAX_CHARS", "120000") or "120000"
    )

    store = SnapshotStore(db_path)
    await run_scheduler(
        store=store,
        interval_seconds=interval_seconds,
        max_cycles=max_cycles,
        enable_security_sweep=enable_security_sweep,
        security_max_targets=security_max_targets,
        retention_days=retention_days if retention_days > 0 else None,
        retention_keep_recent_per_type=retention_keep_recent_per_type,
        compact_every_cycles=compact_every_cycles,
        log_payloads=log_payloads,
        log_payload_max_chars=log_payload_max_chars,
    )


if __name__ == "__main__":
    setup_logging()
    asyncio.run(main())
