# Running 0VRW4TCH — Agents, Tools & Orchestrator

## Prerequisites

```bash
# 1. Clone the repo
git clone <repo-url> /opt/0VRW4TCH
cd /opt/0VRW4TCH

# 2. Install uv (if not already installed)
pip install uv

# 3. Install dependencies
uv sync

# 4. Create .env in project root
cat > .env <<EOF
MODEL_PROVIDER=gemini
DEFAULT_MODEL=gemini-2.5-flash-lite
GOOGLE_API_KEY=<your_google_api_key>
EOF
```

On Linux, also install system network tools:
```bash
sudo apt-get install -y iproute2 net-tools dnsutils lsof
```

---

## Pipeline Architecture

```
secops_pipeline (SequentialAgent)
├── perception_stage (ParallelAgent)
│   ├── scope_scanner          → session state: perception_scope
│   └── system_health          → session state: perception_health
├── analysis_stage (ParallelAgent)
│   ├── anomaly_detector       → session state: analysis_anomalies
│   ├── vulnerability_assessor → session state: analysis_vulnerabilities
│   └── network_monitor        → session state: analysis_network
└── security_magistrate        → session state: decision_verdict
    ├── thought_agent          (reasoning sub-agent)
    └── security_enforcer      → session state: enforcement_result
        Tools: disable_credentials, rotate_credentials, block_network_traffic,
               isolate_system, terminate_process, execute_command, rollback_changes
```

---

## Running the Full Orchestrator Pipeline

Runs all stages sequentially: Perception → Analysis → Decision.

```bash
uv run overwatch
```

Override prompt:
```bash
ADK_PROMPT="Run a full security audit and remediate any critical issues." \
uv run overwatch
```

Override session:
```bash
ADK_USER_ID=my-user ADK_SESSION_ID=run-001 uv run overwatch
```

---

## Running Individual Agents

### network_monitor

```bash
uv run run-network-monitor

# Custom prompt
uv run run-network-monitor --prompt "Check for C2 communication and data exfiltration."
uv run run-network-monitor --prompt "Check for all incoming traffic."
uv run run-network-monitor --prompt "Look for ARP spoofing or DNS hijacking."
```

### agent-health-check

```bash
uv run agent-health-check
```

### system-diagnostics

```bash
uv run system-diagnostics
```

### Any agent (generic pattern)

Use `scripts/run_network_monitor.py` as a reference template:

```python
import asyncio
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from agents.<layer>.<agent>.agent import agent
from config.settings import app_name

async def run():
    session_service = InMemorySessionService()
    runner = Runner(app_name=app_name(), agent=agent, session_service=session_service)
    await session_service.create_session(
        app_name=app_name(), user_id="local", session_id="run-001",
        state={
            "perception_scope": "(not yet available)",
            "perception_health": "(not yet available)",
        }
    )
    msg = types.Content(role="user", parts=[types.Part(text="<your prompt>")])
    async for _ in runner.run_async(user_id="local", session_id="run-001", new_message=msg):
        pass

asyncio.run(run())
```

---

## Running Individual Tools (no LLM)

Call tool functions directly. Useful for debugging or one-off checks.

All commands below use `uv run python -c "..."` — no venv activation needed.

### network_monitor tools

```bash
uv run python -c "
from agents.analysis.network_monitor.tools import (
    assess_network_threats,
    analyze_outbound_connections,
    monitor_active_connections,
    analyze_arp_table,
    analyze_dns_behavior,
    analyze_traffic_volume,
)
import json

# Full threat assessment (calls all sub-tools internally)
print(json.dumps(assess_network_threats(), indent=2))

# All connection states: LISTEN, ESTABLISHED, TIME_WAIT, etc.
print(json.dumps(monitor_active_connections(), indent=2))

# Outbound / exfiltration analysis
print(json.dumps(analyze_outbound_connections(), indent=2))

# ARP spoofing check
print(json.dumps(analyze_arp_table(), indent=2))

# DNS hijacking / unusual resolvers / /etc/hosts overrides
print(json.dumps(analyze_dns_behavior(), indent=2))

# Per-interface traffic volume (cumulative since boot)
print(json.dumps(analyze_traffic_volume(), indent=2))
"
```

### anomaly_detector tools

```bash
uv run python -c "
from agents.analysis.anomaly_detector.tools import detect_system_anomalies
import json
print(json.dumps(detect_system_anomalies(), indent=2))
"
```

### vulnerability_assessor tools

```bash
uv run python -c "
from agents.analysis.vulnerability_assessor.tools import run_scope_security_sweep
import json
print(json.dumps(run_scope_security_sweep(), indent=2))
"
```

### scope_scanner tools

```bash
uv run python -c "
from agents.perception.scope_scanner.sensors import collect_scope_targets
from shared.tools.asset_discovery_tools import discover_runtime_assets
import json
print(json.dumps(collect_scope_targets(), indent=2))
print(json.dumps(discover_runtime_assets(), indent=2))
"
```

### system_health tools

```bash
uv run python -c "
from shared.tools.system_analyzer_tools import analyze_local_system
from shared.tools.monitoring_tools import fetch_metrics
import json
print(json.dumps(analyze_local_system('Check system health'), indent=2))
print(json.dumps(fetch_metrics(), indent=2))
"
```

### security_magistrate tools

```bash
uv run python -c "
from agents.decision.security_magistrate.tools import (
    analyze_threat_signals,
    assess_severity,
    classify_attack_type,
    prioritize_actions,
)
import json

signals = [{
    'source': 'network_monitor',
    'signal_type': 'c2_communication',
    'affected_systems': ['192.168.1.10'],
    'indicators': {}
}]
print(json.dumps(analyze_threat_signals(signals), indent=2))
print(json.dumps(assess_severity('ransomware', affected_systems_count=3), indent=2))
print(json.dumps(classify_attack_type(['c2_communication', 'data_exfiltration'], {}), indent=2))
"
```

### security_enforcer tools

> **Note:** enforcer tools run in mock mode by default (`MOCK_MODE=true`).
> Set `MOCK_MODE=false` in `.env` for real execution — `isolate_system` and
> `terminate_process` will actually disconnect containers / kill processes.

```bash
uv run python -c "
import os; os.environ['MOCK_MODE'] = 'true'
from agents.action.security_enforcer.tools import (
    block_network_traffic,
    isolate_system,
    terminate_process,
    execute_command,
    disable_credentials,
    rotate_credentials,
)
import json

print(json.dumps(block_network_traffic('1.2.3.4', direction='outbound'), indent=2))
print(json.dumps(isolate_system('container/abc123'), indent=2))
print(json.dumps(terminate_process('1234', identifier_type='pid'), indent=2))
"
```

---

## Docker — network_monitor

```bash
# Build
docker build \
  -f deployment/docker/Dockerfile.network_monitor \
  -t network_monitor:latest \
  .

# Run — --network host is required to see real host connections/interfaces
docker run --rm \
  --network host \
  --env-file .env \
  network_monitor:latest

# Custom prompt
docker run --rm \
  --network host \
  --env-file .env \
  network_monitor:latest \
  uv run run-network-monitor \
  --prompt "Check for C2 communication and data exfiltration."
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PROVIDER` | `zai` | `gemini` or `zai` |
| `DEFAULT_MODEL` | `zai/glm-4.5` | Model name (e.g. `gemini-2.5-flash-lite`) |
| `GOOGLE_API_KEY` | — | Required when `MODEL_PROVIDER=gemini` |
| `ZAI_API_KEY` | — | Required when `MODEL_PROVIDER=zai` |
| `MOCK_MODE` | `false` | `true` = enforcer actions are simulated |
| `ADK_PROMPT` | health check | Prompt sent to the orchestrator pipeline |
| `ADK_USER_ID` | `local-user` | Session user identifier |
| `ADK_SESSION_ID` | `local-session` | Session identifier |
| `ADK_SESSION_DB_PATH` | `./data/adk_sessions.db` | SQLite session storage path |
| `ADK_AOP_UI` | `true` | `false` to disable the terminal observability panels |
| `METRICS_BACKEND_URL` | — | Prometheus/VictoriaMetrics URL for live metrics |
| `METRICS_BEARER_TOKEN` | — | Auth token for metrics backend |
