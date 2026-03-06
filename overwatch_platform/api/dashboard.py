"""
Overwatch Dashboard — web UI for monitoring cycle history and status.

Reads from the SnapshotStore SQLite DB and serves a live-updating HTML dashboard.
"""
from __future__ import annotations

import html
import json
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT_DIR / "data" / "overwatch.db"

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _get_cycles(limit: int = 50) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                """
                SELECT id, captured_at, payload_json
                FROM scan_snapshots
                WHERE snapshot_type = 'overwatch_cycle'
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "captured_at": row["captured_at"],
                **json.loads(row["payload_json"]),
            }
            for row in rows
        ]
    except (sqlite3.OperationalError, FileNotFoundError):
        return []


def _get_verdicts(limit: int = 50) -> list[dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                """
                SELECT id, captured_at, payload_json
                FROM scan_snapshots
                WHERE snapshot_type = 'verdict'
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "captured_at": row["captured_at"],
                **json.loads(row["payload_json"]),
            }
            for row in rows
        ]
    except (sqlite3.OperationalError, FileNotFoundError):
        return []


def _get_stats() -> dict[str, Any]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT snapshot_type, count(*) as cnt FROM scan_snapshots GROUP BY snapshot_type"
            ).fetchall()
            counts = {row["snapshot_type"]: row["cnt"] for row in rows}

            latest = conn.execute(
                """
                SELECT captured_at FROM scan_snapshots
                WHERE snapshot_type = 'overwatch_cycle'
                ORDER BY id DESC LIMIT 1
                """
            ).fetchone()

        return {
            "total_cycles": counts.get("overwatch_cycle", 0),
            "total_sweeps": counts.get("sweep", 0),
            "total_verdicts": counts.get("verdict", 0),
            "last_cycle_at": latest["captured_at"] if latest else "never",
        }
    except (sqlite3.OperationalError, FileNotFoundError):
        return {
            "total_cycles": 0,
            "total_sweeps": 0,
            "total_verdicts": 0,
            "last_cycle_at": "never",
        }


def _esc(text: str) -> str:
    """HTML-escape text for safe rendering."""
    return html.escape(str(text))


# ---- JSON API endpoints ----

@router.get("/api/cycles")
async def api_cycles(limit: int = 50) -> list[dict]:
    return _get_cycles(min(limit, 200))


@router.get("/api/verdicts")
async def api_verdicts(limit: int = 10) -> list[dict]:
    return _get_verdicts(min(limit, 50))


@router.get("/api/stats")
async def api_stats() -> dict:
    return _get_stats()


# ---- HTML Dashboard ----

@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> HTMLResponse:
    stats = _get_stats()
    cycles = _get_cycles(30)
    verdicts = _get_verdicts(50)

    # Build verdict lookup by pipeline session ID
    verdict_by_session: dict[str, dict] = {}
    for v in verdicts:
        sid = (v.get("pipeline", {}) or {}).get("session_id", "")
        if sid:
            verdict_by_session[sid] = v

    cycle_rows = ""
    for c in cycles:
        ev = c.get("evaluation", {})
        escalated = c.get("escalated", False)
        cycle_num = c.get("cycle", 0)
        score = ev.get("network_threat_score", 0)
        findings = ev.get("total_findings", 0)
        high_crit = ev.get("high_or_critical_count", 0)
        reasons = ", ".join(ev.get("reasons", [])) or "—"
        session = c.get("pipeline_session") or "—"

        status_class = "escalated" if escalated else "quiet"
        status_text = "ESCALATED" if escalated else "QUIET"

        # Build expandable detail row for escalated cycles
        detail_html = ""
        if escalated and session in verdict_by_session:
            v = verdict_by_session[session]
            pipeline = v.get("pipeline", {})
            verdict_text = _esc(pipeline.get("verdict", "") or "No verdict produced")
            enforcement_text = _esc(pipeline.get("enforcement", "") or "No enforcement actions taken")
            network_raw = pipeline.get("analysis_network", "")
            anomalies_raw = pipeline.get("analysis_anomalies", "")

            # Parse network findings into readable list
            network_findings_html = _render_findings(network_raw, "Network")
            anomaly_findings_html = _render_findings(anomalies_raw, "Anomaly")

            row_id = c.get("id", cycle_num)

            pip_session = _esc(pipeline.get("session_id", ""))

            detail_html = f"""
            <tr class="detail-row" id="detail-{row_id}" style="display:none;">
                <td colspan="8">
                    <div class="detail-content">
                        <div class="detail-section">
                            <div class="detail-label">Verdict</div>
                            <div class="detail-text verdict-text">{verdict_text}</div>
                        </div>
                        <div class="detail-section">
                            <div class="detail-label">Actions Taken / Recommended</div>
                            <div class="detail-text enforcement-text">{enforcement_text}</div>
                        </div>
                        <div class="detail-columns">
                            <div class="detail-section">
                                <div class="detail-label">Network Findings</div>
                                {network_findings_html}
                            </div>
                            <div class="detail-section">
                                <div class="detail-label">Anomaly Findings</div>
                                {anomaly_findings_html}
                            </div>
                        </div>
                        <button class="investigate-btn" onclick="event.stopPropagation(); openChat('{pip_session}', {cycle_num})">
                            Investigate
                        </button>
                    </div>
                </td>
            </tr>"""

        row_id = c.get("id", cycle_num)
        expandable = f' class="expandable" onclick="toggleDetail({row_id})"' if detail_html else ""

        cycle_rows += f"""
        <tr class="{status_class}"{expandable}>
            <td>{cycle_num}</td>
            <td>{c.get('captured_at', '?')[:19]}</td>
            <td><span class="badge {status_class}">{status_text}</span>{f' <span class="expand-icon" id="icon-{row_id}">&#9654;</span>' if detail_html else ''}</td>
            <td>{score:.3f}</td>
            <td>{findings}</td>
            <td>{high_crit}</td>
            <td class="reasons">{reasons}</td>
            <td class="session-id">{session}</td>
        </tr>{detail_html}"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>0VRW4TCH Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
            background: #0a0a0f;
            color: #c8c8d0;
            padding: 24px;
        }}
        h1 {{
            color: #00ff88;
            font-size: 1.6rem;
            margin-bottom: 8px;
            letter-spacing: 2px;
        }}
        .subtitle {{
            color: #666;
            font-size: 0.85rem;
            margin-bottom: 24px;
        }}

        .stats {{
            display: flex;
            gap: 16px;
            margin-bottom: 28px;
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: #12121a;
            border: 1px solid #1e1e2e;
            border-radius: 8px;
            padding: 16px 24px;
            min-width: 160px;
        }}
        .stat-card .label {{
            color: #666;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-card .value {{
            color: #00ff88;
            font-size: 1.8rem;
            font-weight: bold;
            margin-top: 4px;
        }}
        .stat-card .value.warn {{ color: #ffaa00; }}

        h2 {{
            color: #8888aa;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin: 28px 0 12px 0;
            border-bottom: 1px solid #1e1e2e;
            padding-bottom: 8px;
        }}

        .table-wrap {{
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid #1e1e2e;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
        }}
        th {{
            background: #12121a;
            color: #8888aa;
            text-align: left;
            padding: 10px 12px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 1px;
            border-bottom: 1px solid #1e1e2e;
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 8px 12px;
            border-bottom: 1px solid #0e0e16;
        }}
        tr:hover {{ background: #14141e; }}
        tr.escalated {{ background: #1a1210; }}
        tr.escalated:hover {{ background: #201510; }}
        tr.expandable {{ cursor: pointer; }}

        .badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        .badge.quiet {{
            background: #0a2a1a;
            color: #00ff88;
        }}
        .badge.escalated {{
            background: #2a1a0a;
            color: #ffaa00;
        }}
        .expand-icon {{
            color: #ffaa00;
            font-size: 0.7rem;
            margin-left: 6px;
            display: inline-block;
            transition: transform 0.2s;
        }}
        .expand-icon.open {{
            transform: rotate(90deg);
        }}
        .reasons {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #888;
        }}
        .session-id {{
            color: #555;
            font-size: 0.75rem;
        }}

        /* Detail rows */
        .detail-row td {{
            padding: 0;
            border-bottom: 2px solid #ffaa0033;
        }}
        .detail-content {{
            padding: 16px 20px;
            background: #0e0e14;
            border-top: 1px solid #1e1e2e;
        }}
        .detail-section {{
            margin-bottom: 14px;
        }}
        .detail-label {{
            color: #ffaa00;
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 6px;
            font-weight: 600;
        }}
        .detail-text {{
            color: #bbb;
            font-size: 0.8rem;
            line-height: 1.6;
            white-space: pre-wrap;
            max-height: 250px;
            overflow-y: auto;
            padding: 10px 12px;
            background: #12121a;
            border-radius: 6px;
            border: 1px solid #1a1a2a;
        }}
        .enforcement-text {{
            border-left: 3px solid #ff4444;
        }}
        .detail-columns {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        @media (max-width: 900px) {{
            .detail-columns {{ grid-template-columns: 1fr; }}
        }}

        /* Finding items */
        .finding-list {{
            list-style: none;
            padding: 0;
        }}
        .finding-item {{
            padding: 8px 10px;
            background: #12121a;
            border-radius: 4px;
            border: 1px solid #1a1a2a;
            margin-bottom: 6px;
            font-size: 0.78rem;
        }}
        .finding-item .sev {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 0.65rem;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 6px;
        }}
        .sev.critical {{ background: #3a0a0a; color: #ff4444; }}
        .sev.high {{ background: #2a1a0a; color: #ffaa00; }}
        .sev.medium {{ background: #1a1a0a; color: #aaaa00; }}
        .sev.low {{ background: #0a1a0a; color: #44aa44; }}
        .finding-desc {{ color: #aaa; }}

        .empty {{ color: #444; font-style: italic; padding: 20px; }}
        .refresh-note {{
            color: #333;
            font-size: 0.7rem;
            text-align: right;
            margin-top: 16px;
        }}

        /* Investigate button */
        .investigate-btn {{
            background: #1a2a3a;
            color: #44aaff;
            border: 1px solid #2a3a5a;
            padding: 8px 20px;
            border-radius: 6px;
            font-family: inherit;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-top: 8px;
            transition: all 0.2s;
        }}
        .investigate-btn:hover {{
            background: #2a3a5a;
            color: #66ccff;
        }}

        /* Chat panel */
        .chat-overlay {{
            display: none;
            position: fixed;
            top: 0; right: 0; bottom: 0;
            width: 480px;
            background: #0c0c14;
            border-left: 2px solid #1e1e2e;
            z-index: 1000;
            flex-direction: column;
            box-shadow: -4px 0 20px rgba(0,0,0,0.5);
        }}
        .chat-overlay.open {{
            display: flex;
        }}
        .chat-header {{
            padding: 14px 18px;
            background: #12121a;
            border-bottom: 1px solid #1e1e2e;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .chat-title {{
            color: #44aaff;
            font-size: 0.85rem;
            font-weight: 600;
        }}
        .chat-close {{
            background: none;
            border: none;
            color: #666;
            font-size: 1.2rem;
            cursor: pointer;
            padding: 4px 8px;
        }}
        .chat-close:hover {{ color: #ff4444; }}
        .chat-messages {{
            flex: 1;
            overflow-y: auto;
            padding: 16px;
        }}
        .chat-msg {{
            margin-bottom: 12px;
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 0.8rem;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .chat-msg.user {{
            background: #1a2a3a;
            color: #aaccee;
            border: 1px solid #2a3a5a;
            margin-left: 40px;
        }}
        .chat-msg.assistant {{
            background: #12121a;
            color: #bbb;
            border: 1px solid #1a1a2a;
            margin-right: 40px;
        }}
        .chat-msg.system {{
            background: #1a1a0a;
            color: #aaaa66;
            border: 1px solid #2a2a1a;
            font-size: 0.75rem;
            text-align: center;
        }}
        .chat-msg.loading {{
            color: #555;
            font-style: italic;
        }}
        .chat-msg.tool-trace {{
            background: #0a0f14;
            border: 1px solid #1a2a3a;
            padding: 8px 12px;
            font-size: 0.75rem;
        }}
        .tool-header {{
            color: #668899;
            font-weight: 600;
            margin-bottom: 6px;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .tool-call-item {{
            padding: 4px 0;
            border-bottom: 1px solid #111822;
        }}
        .tool-call-item:last-child {{ border-bottom: none; }}
        .tool-name {{
            color: #44aaff;
            font-weight: 600;
            margin-right: 4px;
        }}
        .tool-args {{
            color: #888;
        }}
        .chat-input-wrap {{
            padding: 12px 16px;
            background: #12121a;
            border-top: 1px solid #1e1e2e;
            display: flex;
            gap: 8px;
        }}
        .chat-input {{
            flex: 1;
            background: #0a0a12;
            color: #ccc;
            border: 1px solid #2a2a3a;
            border-radius: 6px;
            padding: 10px 14px;
            font-family: inherit;
            font-size: 0.82rem;
            outline: none;
            resize: none;
        }}
        .chat-input:focus {{
            border-color: #44aaff;
        }}
        .chat-input::placeholder {{ color: #444; }}
        .chat-send {{
            background: #1a2a3a;
            color: #44aaff;
            border: 1px solid #2a3a5a;
            border-radius: 6px;
            padding: 10px 16px;
            font-family: inherit;
            font-size: 0.82rem;
            cursor: pointer;
            font-weight: 600;
        }}
        .chat-send:hover {{ background: #2a3a5a; }}
        .chat-send:disabled {{
            opacity: 0.4;
            cursor: not-allowed;
        }}

        /* Quick action buttons */
        .quick-actions {{
            padding: 8px 16px;
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            border-bottom: 1px solid #1e1e2e;
        }}
        .quick-btn {{
            background: #0a0a12;
            color: #888;
            border: 1px solid #1a1a2a;
            border-radius: 4px;
            padding: 4px 10px;
            font-family: inherit;
            font-size: 0.7rem;
            cursor: pointer;
        }}
        .quick-btn:hover {{
            color: #44aaff;
            border-color: #2a3a5a;
        }}

        @media (max-width: 600px) {{
            .chat-overlay {{ width: 100%; }}
        }}
    </style>
</head>
<body>
    <h1>0VRW4TCH</h1>
    <p class="subtitle">Autonomous Security Monitoring Dashboard</p>

    <div class="stats">
        <div class="stat-card">
            <div class="label">Total Cycles</div>
            <div class="value">{stats['total_cycles']}</div>
        </div>
        <div class="stat-card">
            <div class="label">Escalations</div>
            <div class="value warn">{stats['total_verdicts']}</div>
        </div>
        <div class="stat-card">
            <div class="label">Sweeps</div>
            <div class="value">{stats['total_sweeps']}</div>
        </div>
        <div class="stat-card">
            <div class="label">Last Cycle</div>
            <div class="value" style="font-size:0.9rem;">{stats['last_cycle_at'][:19] if stats['last_cycle_at'] != 'never' else 'never'}</div>
        </div>
    </div>

    <h2>Cycle History <span style="color:#555; font-size:0.7rem; text-transform:none;">(click escalated rows to expand)</span></h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Cycle</th>
                    <th>Time</th>
                    <th>Status</th>
                    <th>Threat Score</th>
                    <th>Findings</th>
                    <th>High/Crit</th>
                    <th>Reasons</th>
                    <th>Session</th>
                </tr>
            </thead>
            <tbody>
                {cycle_rows if cycle_rows else '<tr><td colspan="8" class="empty">No cycles recorded yet. Start overwatch to see data.</td></tr>'}
            </tbody>
        </table>
    </div>

    <p class="refresh-note">Auto-refreshes every 30s — pauses while chat is open</p>

    <!-- Chat Panel -->
    <div class="chat-overlay" id="chatPanel">
        <div class="chat-header">
            <span class="chat-title" id="chatTitle">Investigate Escalation</span>
            <button class="chat-close" onclick="closeChat()">&times;</button>
        </div>
        <div class="quick-actions">
            <button class="quick-btn" onclick="quickMsg('Summarize the key threats found')">Summarize threats</button>
            <button class="quick-btn" onclick="quickMsg('What immediate actions should I take?')">Action plan</button>
            <button class="quick-btn" onclick="quickMsg('Which findings are false positives?')">False positives?</button>
            <button class="quick-btn" onclick="quickMsg('Give me the exact commands to remediate the critical findings')">Remediation commands</button>
            <button class="quick-btn" onclick="quickMsg('What should I monitor going forward?')">Monitoring plan</button>
        </div>
        <div class="chat-messages" id="chatMessages"></div>
        <div class="chat-input-wrap">
            <textarea class="chat-input" id="chatInput" placeholder="Ask about this escalation..." rows="1"
                      onkeydown="if(event.key==='Enter' && !event.shiftKey){{ event.preventDefault(); sendChat(); }}"></textarea>
            <button class="chat-send" id="chatSend" onclick="sendChat()">Send</button>
        </div>
    </div>

    <script>
        let currentSessionId = null;
        let chatOpen = false;

        // JS-based auto-refresh that pauses when chat is open
        setInterval(() => {{
            if (!chatOpen) window.location.reload();
        }}, 30000);

        function toggleDetail(rowId) {{
            const row = document.getElementById('detail-' + rowId);
            const icon = document.getElementById('icon-' + rowId);
            if (!row) return;
            if (row.style.display === 'none') {{
                row.style.display = 'table-row';
                if (icon) icon.classList.add('open');
            }} else {{
                row.style.display = 'none';
                if (icon) icon.classList.remove('open');
            }}
        }}

        function openChat(sessionId, cycleNum) {{
            currentSessionId = sessionId;
            chatOpen = true;

            document.getElementById('chatTitle').textContent = 'Investigate — Cycle ' + cycleNum + ' (' + sessionId + ')';
            document.getElementById('chatPanel').classList.add('open');
            document.getElementById('chatMessages').innerHTML =
                '<div class="chat-msg system">Chat connected to escalation ' + sessionId +
                '. Ask questions about findings, plan actions, or request remediation commands.</div>';
            document.getElementById('chatInput').focus();
        }}

        function closeChat() {{
            chatOpen = false;
            currentSessionId = null;
            document.getElementById('chatPanel').classList.remove('open');
        }}

        function quickMsg(text) {{
            document.getElementById('chatInput').value = text;
            sendChat();
        }}

        async function sendChat() {{
            const input = document.getElementById('chatInput');
            const btn = document.getElementById('chatSend');
            const messages = document.getElementById('chatMessages');
            const text = input.value.trim();

            if (!text || !currentSessionId) return;

            // Show user message
            const userDiv = document.createElement('div');
            userDiv.className = 'chat-msg user';
            userDiv.textContent = text;
            messages.appendChild(userDiv);

            // Show loading
            const loadDiv = document.createElement('div');
            loadDiv.className = 'chat-msg assistant loading';
            loadDiv.textContent = 'Investigating (may run diagnostic tools)...';
            messages.appendChild(loadDiv);

            input.value = '';
            btn.disabled = true;
            messages.scrollTop = messages.scrollHeight;

            try {{
                const resp = await fetch('/dashboard/api/chat/send', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        session_id: currentSessionId,
                        message: text,
                    }}),
                }});
                const data = await resp.json();

                // Show tool calls if any
                if (data.tool_calls && data.tool_calls.length > 0) {{
                    loadDiv.remove();
                    const toolDiv = document.createElement('div');
                    toolDiv.className = 'chat-msg tool-trace';
                    let toolHtml = '<div class="tool-header">Tools executed:</div>';
                    data.tool_calls.forEach(tc => {{
                        const argsStr = Object.entries(tc.args || {{}}).map(([k,v]) => k + '=' + v).join(', ');
                        toolHtml += '<div class="tool-call-item">' +
                            '<span class="tool-name">' + tc.tool + '</span>' +
                            '<span class="tool-args">(' + argsStr + ')</span>' +
                            '</div>';
                    }});
                    toolDiv.innerHTML = toolHtml;
                    messages.appendChild(toolDiv);

                    const replyDiv = document.createElement('div');
                    replyDiv.className = 'chat-msg assistant';
                    replyDiv.textContent = data.reply || 'No response.';
                    messages.appendChild(replyDiv);
                }} else {{
                    loadDiv.className = 'chat-msg assistant';
                    loadDiv.textContent = data.reply || 'No response.';
                }}
            }} catch (err) {{
                loadDiv.className = 'chat-msg assistant';
                loadDiv.textContent = 'Error: ' + err.message;
                loadDiv.style.color = '#ff4444';
            }}

            btn.disabled = false;
            messages.scrollTop = messages.scrollHeight;
            input.focus();
        }}
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)


def _render_findings(raw: str, label: str) -> str:
    """Parse findings from agent output and render as HTML list."""
    if not raw:
        return '<p class="empty">No findings</p>'

    # Try to parse as JSON array
    findings = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            findings = parsed
        elif isinstance(parsed, dict):
            findings = parsed.get("findings", [])
    except (json.JSONDecodeError, ValueError):
        # Not JSON — render as plain text
        return f'<div class="detail-text">{_esc(str(raw)[:1000])}</div>'

    if not findings:
        # Raw text output from agent
        text = str(raw)[:1000]
        return f'<div class="detail-text">{_esc(text)}</div>'

    items = ""
    for f in findings[:15]:
        if not isinstance(f, dict):
            items += f'<li class="finding-item"><span class="finding-desc">{_esc(str(f)[:200])}</span></li>'
            continue
        sev = str(f.get("severity", f.get("signal_type", "info"))).lower()
        sev_class = sev if sev in ("critical", "high", "medium", "low") else "low"
        desc = f.get("description", f.get("signal_type", "Unknown finding"))
        signal = f.get("signal_type", "")
        items += f"""<li class="finding-item">
            <span class="sev {sev_class}">{_esc(sev)}</span>
            {('<span style="color:#666;">[' + _esc(signal) + ']</span> ') if signal else ''}
            <span class="finding-desc">{_esc(str(desc)[:200])}</span>
        </li>"""

    remaining = len(findings) - 15
    if remaining > 0:
        items += f'<li class="finding-item" style="color:#555;">... and {remaining} more</li>'

    return f'<ul class="finding-list">{items}</ul>'
