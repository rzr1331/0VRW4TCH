# 0VRW4TCH — Autonomous Multi-Agent SecOps Platform

An autonomous security operations platform built on [Google ADK](https://github.com/google/adk-python). A deterministic pipeline of specialized AI agents performs asset discovery, health checks, anomaly detection, vulnerability assessment, and automated remediation — end-to-end, in a single run.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      secops_pipeline                             │
│                    (SequentialAgent)                             │
│                                                                  │
│  ┌─ Stage 1: Perception (Parallel) ──────────────────────────┐   │
│  │  scope_scanner  ∥  system_health                          │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          ↓                                       │
│  ┌─ Stage 2: Analysis (Parallel) ────────────────────────────┐   │
│  │  anomaly_detector  ∥  vulnerability_assessor              │   │
│  └───────────────────────────────────────────────────────────┘   │
│                          ↓                                       │
│  ┌─ Stage 3: Decision ───────────────────────────────────────┐   │
│  │  security_magistrate                                      │   │
│  │    ├── thought (chain-of-thought reasoning)               │   │
│  │    └── security_enforcer (remediation actions)            │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### Pipeline Stages

| Stage | Agent | Purpose |
|---|---|---|
| **Perception** | `scope_scanner` | Discovers in-scope assets, services, and monitoring targets |
| | `system_health` | Evaluates runtime health, metrics, and security coverage |
| **Analysis** | `anomaly_detector` | Scores anomalies and surfaces evidence-backed findings |
| | `vulnerability_assessor` | Runs targeted security checks for discovered risk areas |
| **Decision** | `security_magistrate` | Produces a verdict with severity assessment and action plan |
| | `thought` | Chain-of-thought reasoning sub-agent |
| | `security_enforcer` | Executes remediation actions (with human confirmation for high-risk ops) |

### Observability & Safety

- **Rich terminal UI** — CTF-agent-style panels with step counters, timing, nested output, and token metrics
- **Audit plugin** — structured JSONL audit trail at `data/audit/audit.jsonl` logging every agent lifecycle event and tool invocation
- **Guardrails** — blocked shell commands, prompt injection detection, and human-confirmation gates for dangerous operations (configured in `config/policies/guardrails.yaml`)

## Quick Start

### Prerequisites
- Python ≥ 3.11
- [uv](https://docs.astral.sh/uv/) package manager

### Setup

```bash
git clone <repo-url> && cd 0VRW4TCH
cp .env.example .env       # edit with your API keys
uv venv
uv sync
```

### Run

```bash
uv run --project ./ -m secops_platform.orchestrator.orchestrator
```

### Run Integration Tests

```bash
# All tests
uv run --project ./ -m pytest tests/ -q

# Single scenario
uv run --project ./ -m tests.integration.runner --scenario container_escape
```

## Configuration

All runtime config is read from environment variables (see `.env.example`).

### Model Provider

```bash
# Google Gemini (default)
MODEL_PROVIDER=gemini
DEFAULT_MODEL=gemini-2.5-flash-lite

# Z.AI (GLM via LiteLLM)
MODEL_PROVIDER=zai
DEFAULT_MODEL=zai/glm-4.5
ZAI_API_KEY=your_key
```

Per-agent overrides: `MODEL_SCOPE_SCANNER`, `MODEL_MAGISTRATE`, etc.

### Session Storage

SQLite by default at `./data/adk_sessions.db`. Override with:

```bash
ADK_SESSION_DB_URL="postgresql+asyncpg://user:pass@localhost:5432/secops"
```

### Memory (Long-term Recall)

```bash
ADK_MEMORY_BACKEND=in_memory        # default, local dev
ADK_MEMORY_BACKEND=vertex           # persistent, requires GCP
```

### Live Metrics

Connect to Prometheus or VictoriaMetrics for real system metrics:

```bash
METRICS_BACKEND_URL="http://your-prometheus:9090"
METRICS_BEARER_TOKEN="your-token-if-needed"
```

## Project Structure

```
agents/
├── stages.py                    # Pipeline definition (SequentialAgent → Parallel → Decision)
├── perception/
│   ├── scope_scanner/           # Asset discovery
│   └── system_health/           # Runtime health checks
├── analysis/
│   ├── anomaly_detector/        # Anomaly scoring
│   ├── vulnerability_assessor/  # Security scans
│   └── thought_agent/           # Chain-of-thought reasoning
├── decision/
│   └── security_magistrate/     # Verdict + severity + action plan
└── action/
    └── security_enforcer/       # Remediation execution

config/
├── settings.py                  # Runtime config (models, providers)
├── constants.py                 # Domain constants (severity weights, attack types)
└── policies/
    └── guardrails.yaml          # Blocked commands, confirmation gates, injection patterns

shared/
├── adk/
│   ├── observability.py         # Rich terminal UI callbacks (timing, tokens, nested panels)
│   └── audit_plugin.py          # JSONL audit trail plugin
├── security/
│   ├── policy_loader.py         # YAML policy file loader
│   └── mock_signals.py          # Mock threat signals for testing
├── security_tools/              # Shared tool implementations (code exec, SSH, Linux commands)
├── tools/                       # Common tools (discovery, metrics, security scans)
├── models/                      # Pydantic models and output contracts
└── utils/
    ├── terminal_ui.py           # ANSI panel renderer (compact, rich, nested)
    └── env.py                   # Environment variable helpers

secops_platform/
└── orchestrator/
    ├── orchestrator.py          # Entry point (~65 lines)
    ├── runner_factory.py        # ADK Runner/Session/Memory wiring
    └── cli.py                   # Startup banner + conclusion report

tests/
├── unit/                        # Pipeline structure, guardrails, audit plugin tests
└── integration/                 # Attack scenario tests (ransomware, cryptomining, etc.)
```

## Optional Tool Behavior

Discovery and security scans are best-effort. Missing tools (`kubectl`, `falco`, `trivy`, `nmap`, etc.) do not fail execution — the platform returns partial results with explicit `missing_tools` and `warnings` fields so it works across heterogeneous environments.

## Notes

- Agent definitions are Python-only under `agents/` (no YAML mirror)
- All pipeline results are read from ADK session state, not scraped from tool responses
- High-risk enforcer tools require human confirmation before execution
- Set `ADK_AOP_UI=false` to disable the rich observability output