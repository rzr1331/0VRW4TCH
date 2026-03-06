"""
0VRW4TCH — continuous agentic security monitoring service.

Unifies the scheduler (heartbeat) and orchestrator (brain) into a single
long-running service:

    1. Run a fast tool sweep every cycle (scope, health, network, anomalies)
    2. Evaluate findings against thresholds
    3. If thresholds are breached → invoke the full LLM agent pipeline
    4. Store snapshots, verdicts, and actions to SQLite
    5. Sleep until next cycle

Usage:
    uv run overwatch
    uv run overwatch --interval 120 --threat-threshold 0.3
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")

from google.genai.types import Content, Part

from agents.analysis.network_monitor.tools import assess_network_threats
from agents.perception.scope_scanner.sensors import collect_scope_targets
from shared.tools.system_analyzer_tools import analyze_local_system
from shared.utils.env import env_value
from shared.utils.logging import setup_logging
from shared.utils.terminal_ui import Ansi, print_panel
from config.settings import app_name

from overwatch_platform.orchestrator.runner_factory import create_runner, ensure_session
from overwatch_platform.orchestrator.scheduler import SnapshotStore, _analysis_findings
from overwatch_platform.orchestrator.cli import print_conclusion

logger = logging.getLogger("overwatch")


# ---------------------------------------------------------------------------
# Sweep: fast tool-only data collection (no LLM)
# ---------------------------------------------------------------------------

def _run_sweep(cycle: int) -> dict[str, Any]:
    """Execute a fast tool sweep and return raw signals."""
    captured_at = datetime.now(UTC).isoformat()
    signals: dict[str, Any] = {"captured_at": captured_at, "cycle": cycle}

    # 1. Scope scan
    logger.info("sweep: [1/3] scope_scan starting")
    try:
        signals["scope"] = collect_scope_targets()
        logger.info("sweep: [1/3] scope_scan done")
    except Exception as exc:
        logger.warning("sweep: [1/3] scope_scan failed: %s", exc)
        signals["scope"] = {"assets": [], "error": str(exc)}

    # 2. System analysis (health + anomalies)
    logger.info("sweep: [2/3] system_analysis starting")
    try:
        signals["system"] = analyze_local_system("overwatch scheduled analysis")
        logger.info("sweep: [2/3] system_analysis done")
    except Exception as exc:
        logger.warning("sweep: [2/3] system_analysis failed: %s", exc)
        signals["system"] = {"analysis": {"findings": []}, "error": str(exc)}

    # 3. Network threat assessment
    logger.info("sweep: [3/3] network_assessment starting")
    try:
        signals["network"] = assess_network_threats()
        logger.info("sweep: [3/3] network_assessment done")
    except Exception as exc:
        logger.warning("sweep: [3/3] network_assessment failed: %s", exc)
        signals["network"] = {"findings": [], "threat_score": 0.0, "error": str(exc)}

    return signals


# ---------------------------------------------------------------------------
# Evaluate: decide if the agent pipeline should be invoked
# ---------------------------------------------------------------------------

def _evaluate_signals(
    signals: dict[str, Any],
    *,
    threat_threshold: float,
    finding_threshold: int,
) -> dict[str, Any]:
    """Score the sweep and decide whether to escalate to the agent pipeline."""
    network = signals.get("network", {})
    system = signals.get("system", {})

    network_score = float(network.get("threat_score", 0.0))
    network_findings = network.get("findings", [])
    system_findings = _analysis_findings(system)

    high_or_critical = sum(
        1 for f in (network_findings + system_findings)
        if isinstance(f, dict) and str(f.get("severity", "")).lower() in ("high", "critical")
    )
    total_findings = len(network_findings) + len(system_findings)

    should_escalate = (
        network_score >= threat_threshold
        or high_or_critical > 0
        or total_findings >= finding_threshold
    )

    reasons = []
    if network_score >= threat_threshold:
        reasons.append(f"network threat score {network_score:.2f} >= {threat_threshold}")
    if high_or_critical > 0:
        reasons.append(f"{high_or_critical} high/critical findings")
    if total_findings >= finding_threshold:
        reasons.append(f"{total_findings} total findings >= {finding_threshold}")

    return {
        "should_escalate": should_escalate,
        "network_threat_score": network_score,
        "high_or_critical_count": high_or_critical,
        "total_findings": total_findings,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Escalate: invoke the full LLM agent pipeline
# ---------------------------------------------------------------------------

async def _run_pipeline(signals: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
    """Run the full SecOps agent pipeline with context from the sweep."""
    runner, session_service = await create_runner()
    user_id = "overwatch"
    session_id = f"overwatch-{uuid.uuid4().hex[:8]}"
    await ensure_session(session_service, user_id, session_id)

    # Build a context-rich prompt from the sweep signals
    network = signals.get("network", {})
    system_findings = _analysis_findings(signals.get("system", {}))
    scope_summary = (
        signals.get("scope", {}).get("summary", {})
        if isinstance(signals.get("scope"), dict) else {}
    )

    prompt = (
        "0VRW4TCH ALERT: Automated sweep detected findings that require investigation.\n\n"
        f"Escalation reasons: {', '.join(evaluation.get('reasons', ['unknown']))}\n\n"
        f"Network threat score: {evaluation.get('network_threat_score', 0):.2f}\n"
        f"Network findings: {json.dumps(network.get('findings', []), default=str)[:2000]}\n\n"
        f"System findings ({len(system_findings)}): "
        f"{json.dumps(system_findings[:10], default=str)[:2000]}\n\n"
        f"Asset scope: {json.dumps(scope_summary, default=str)[:500]}\n\n"
        "Investigate all findings. Correlate signals across network, system, and assets. "
        "Produce a verdict with severity assessment. If critical threats are confirmed, "
        "recommend or execute remediation actions."
    )

    logger.info("pipeline: starting agent pipeline session=%s", session_id)

    event_count = 0
    async for _event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=Content(role="user", parts=[Part(text=prompt)]),
    ):
        event_count += 1

    session = await session_service.get_session(
        app_name=app_name(), user_id=user_id, session_id=session_id,
    )
    state = session.state if session else {}

    logger.info("pipeline: completed events=%s", event_count)
    print_conclusion(state, event_count=event_count)

    return {
        "session_id": session_id,
        "event_count": event_count,
        "verdict": state.get("decision_verdict", ""),
        "enforcement": state.get("enforcement_result", ""),
        "analysis_network": state.get("analysis_network", ""),
        "analysis_anomalies": state.get("analysis_anomalies", ""),
        "perception_scope": state.get("perception_scope", ""),
        "perception_health": state.get("perception_health", ""),
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def run_overwatch(
    *,
    interval_seconds: int = 300,
    max_cycles: int | None = None,
    threat_threshold: float = 0.3,
    finding_threshold: int = 5,
    db_path: Path | None = None,
) -> None:
    """Run the overwatch loop."""
    resolved_db = db_path or ROOT_DIR / "data" / "overwatch.db"
    store = SnapshotStore(resolved_db)

    # Silence noisy loggers
    for name in (
        "httpx",
        "google_adk.google.adk.models.google_llm",
        "google_adk.google.adk.sessions.database_session_service",
        "google_genai.types",
    ):
        logging.getLogger(name).setLevel(logging.ERROR)

    logger.info(
        "overwatch_start interval=%ss threat_threshold=%.2f finding_threshold=%s max_cycles=%s db=%s",
        interval_seconds, threat_threshold, finding_threshold, max_cycles, resolved_db,
    )

    print_panel("0VRW4TCH — Starting", [
        ("Interval", f"{interval_seconds}s"),
        ("Threat Threshold", f"{threat_threshold}"),
        ("Finding Threshold", f"{finding_threshold}"),
        ("Max Cycles", str(max_cycles or "unlimited")),
        ("Database", str(resolved_db)),
    ], Ansi.BLUE)

    cycle = 0
    while max_cycles is None or cycle < max_cycles:
        cycle += 1
        cycle_start = datetime.now(UTC)

        # --- Sweep ---
        print_panel(f"0VRW4TCH — Cycle {cycle}", [
            ("Status", "Running tool sweep..."),
            ("Time", cycle_start.strftime("%H:%M:%S UTC")),
        ], Ansi.CYAN)

        signals = _run_sweep(cycle)

        # Store raw sweep
        store.insert_snapshot("sweep", signals, captured_at=signals["captured_at"])

        # --- Evaluate ---
        evaluation = _evaluate_signals(
            signals,
            threat_threshold=threat_threshold,
            finding_threshold=finding_threshold,
        )

        logger.info(
            "overwatch_sweep cycle=%s network_score=%.3f findings=%s high_critical=%s escalate=%s",
            cycle,
            evaluation["network_threat_score"],
            evaluation["total_findings"],
            evaluation["high_or_critical_count"],
            evaluation["should_escalate"],
        )

        sweep_rows = [
            ("Network Score", f"{evaluation['network_threat_score']:.3f}"),
            ("Total Findings", str(evaluation["total_findings"])),
            ("High/Critical", str(evaluation["high_or_critical_count"])),
            ("Escalate", str(evaluation["should_escalate"])),
        ]
        if evaluation["reasons"]:
            sweep_rows.append(("Reasons", ", ".join(evaluation["reasons"])))

        print_panel(f"0VRW4TCH — Cycle {cycle} Sweep Results", sweep_rows,
                    Ansi.YELLOW if evaluation["should_escalate"] else Ansi.GREEN)

        # --- Escalate if needed ---
        pipeline_result: dict[str, Any] | None = None
        if evaluation["should_escalate"]:
            logger.info("overwatch_escalate cycle=%s reasons=%s", cycle, evaluation["reasons"])
            print_panel(f"0VRW4TCH — Cycle {cycle} Escalation", [
                ("Action", "Invoking agent pipeline..."),
                ("Reasons", ", ".join(evaluation["reasons"])),
            ], Ansi.YELLOW)

            try:
                pipeline_result = await _run_pipeline(signals, evaluation)
                store.insert_snapshot("verdict", {
                    "cycle": cycle,
                    "evaluation": evaluation,
                    "pipeline": pipeline_result,
                }, captured_at=signals["captured_at"])
            except Exception as exc:
                logger.exception("overwatch_pipeline_error cycle=%s error=%s", cycle, exc)
                print_panel(f"0VRW4TCH — Cycle {cycle} Pipeline Error", [
                    ("Error", str(exc)[:300]),
                ], Ansi.RED)
        else:
            logger.info("overwatch_quiet cycle=%s — no escalation needed", cycle)
            # Print a quiet-cycle summary from sweep data
            network = signals.get("network", {})
            system = signals.get("system", {})
            scope = signals.get("scope", {})
            quiet_rows: list[tuple[str, Any]] = [
                ("Status", "All clear — no escalation needed"),
                ("Network Score", f"{evaluation['network_threat_score']:.3f}"),
                ("Findings", f"{evaluation['total_findings']} total, {evaluation['high_or_critical_count']} high/critical"),
            ]
            scope_summary = scope.get("summary", {}) if isinstance(scope, dict) else {}
            if scope_summary:
                quiet_rows.append(("Assets", str(scope_summary)[:200]))
            sys_health = system.get("analysis", {}).get("health_status", "") if isinstance(system, dict) else ""
            if sys_health:
                quiet_rows.append(("System Health", sys_health))
            net_findings = network.get("findings", [])
            if net_findings:
                brief = ", ".join(
                    f.get("description", f.get("type", "unknown"))[:60]
                    for f in net_findings[:3] if isinstance(f, dict)
                )
                quiet_rows.append(("Top Findings", brief))
            print_panel(f"0VRW4TCH — Cycle {cycle} Summary", quiet_rows, Ansi.GREEN)

        # Store cycle summary
        store.insert_snapshot("overwatch_cycle", {
            "cycle": cycle,
            "captured_at": signals["captured_at"],
            "evaluation": evaluation,
            "escalated": evaluation["should_escalate"],
            "pipeline_session": pipeline_result.get("session_id") if pipeline_result else None,
        }, captured_at=signals["captured_at"])

        # --- Sleep ---
        if max_cycles is not None and cycle >= max_cycles:
            break

        elapsed = (datetime.now(UTC) - cycle_start).total_seconds()
        sleep_for = max(0.0, interval_seconds - elapsed)
        if sleep_for > 0:
            logger.info("overwatch_sleep cycle=%s sleep=%.0fs", cycle, sleep_for)
            await asyncio.sleep(sleep_for)

    logger.info("overwatch_stop cycles_completed=%s", cycle)
    print_panel("0VRW4TCH — Stopped", [("Cycles Completed", str(cycle))], Ansi.BLUE)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="0VRW4TCH — continuous agentic security monitoring.")
    parser.add_argument("--interval", type=int, default=int(env_value("OVERWATCH_INTERVAL", "300") or "300"),
                        help="Seconds between sweep cycles (default: 300)")
    parser.add_argument("--max-cycles", type=int, default=None,
                        help="Stop after N cycles (default: run forever)")
    parser.add_argument("--threat-threshold", type=float, default=0.3,
                        help="Network threat score threshold for escalation (default: 0.3)")
    parser.add_argument("--finding-threshold", type=int, default=5,
                        help="Total finding count threshold for escalation (default: 5)")
    parser.add_argument("--db", type=str, default=None,
                        help="SQLite database path (default: data/overwatch.db)")
    args = parser.parse_args()

    setup_logging()

    db_path = Path(args.db) if args.db else None
    if db_path and not db_path.is_absolute():
        db_path = ROOT_DIR / db_path

    asyncio.run(run_overwatch(
        interval_seconds=args.interval,
        max_cycles=args.max_cycles,
        threat_threshold=args.threat_threshold,
        finding_threshold=args.finding_threshold,
        db_path=db_path,
    ))


if __name__ == "__main__":
    main()
