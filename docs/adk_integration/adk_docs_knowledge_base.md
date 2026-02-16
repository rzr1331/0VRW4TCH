# Google ADK Knowledge Base (Cross-Thread Reference)

## Purpose
This document is a repo-local, reusable reference for Google ADK concepts, terminology, architecture, and learning links. It is designed so any future thread can point to this file and continue from the same baseline.

Primary docs root: <https://google.github.io/adk-docs/>

## Canonical Source Index
Use these first when you want complete coverage:
- Full docs dump: <https://google.github.io/adk-docs/llms-full.txt>
- Compact index: <https://google.github.io/adk-docs/llms.txt>
- Main docs portal: <https://google.github.io/adk-docs/>
- Technical overview: <https://google.github.io/adk-docs/get-started/about/>

## ADK Mental Model
ADK is an event-driven agent runtime:

1. User input enters a `Runner`.
2. `Runner` invokes an `Agent` (LLM or workflow).
3. Agent may call tools, delegate to sub-agents, and emit events/actions.
4. Runtime persists state/artifacts/memory through services.
5. Final response is emitted, with optional streaming and resume support.

High-level flow:
`Input -> Runner -> Agent -> Tool/Model Calls -> Events/Actions -> Session/Artifact/Memory persistence -> Output`

## Core Building Blocks

### 1) Runner and Runtime
- `Runner` is the execution orchestrator for calls to agents.
- Runtime handles invocation lifecycle, streaming, resumability, context, and service integration.
- `RunConfig` controls per-invocation behavior.

Read:
- <https://google.github.io/adk-docs/runtime/>
- <https://google.github.io/adk-docs/runtime/runconfig/>
- <https://google.github.io/adk-docs/runtime/resume/>
- <https://google.github.io/adk-docs/runtime/api-server/>

### 2) Agent Types
- `LlmAgent`: model-driven reasoning and tool selection.
- Workflow agents:
  - `SequentialAgent`: fixed ordered stages.
  - `ParallelAgent`: concurrent branches.
  - `LoopAgent`: iterative refinement/processing.
- Custom `BaseAgent`: full behavior control when defaults do not fit.

Read:
- <https://google.github.io/adk-docs/agents/>
- <https://google.github.io/adk-docs/agents/llm-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/sequential-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/parallel-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/loop-agents/>
- <https://google.github.io/adk-docs/agents/config/>

### 3) Multi-Agent Composition
- Agents can delegate to other agents for specialization.
- Common patterns:
  - delegation/transfer to a focused agent,
  - exposing an agent as a callable tool,
  - orchestration trees or pipelines.
- Keep boundaries explicit: each agent owns one responsibility.

Read:
- <https://google.github.io/adk-docs/agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/>

### 4) Models and Provider Configuration
- Models can be referenced directly (Gemini/Vertex) or through wrappers.
- Provider adapters include external/proxy options for enterprise routing.
- Authentication strategy differs by backend.

Read:
- <https://google.github.io/adk-docs/agents/models/>

### 5) Tools (Capability Surface)
Tools are how agents act beyond pure text generation.

- Function tools: wrap Python functions.
- Long-running tools: async/extended tasks.
- OpenAPI tools: generate tool interfaces from OpenAPI specs.
- MCP tools: import tools exposed by MCP servers.
- Confirmation/auth policies: gate sensitive tool actions.
- Performance guidance: reduce latency/overhead in tool execution.

Read:
- <https://google.github.io/adk-docs/tools-custom/>
- <https://google.github.io/adk-docs/tools-custom/function-tools/>
- <https://google.github.io/adk-docs/tools-custom/openapi-tools/>
- <https://google.github.io/adk-docs/tools-custom/mcp-tools/>
- <https://google.github.io/adk-docs/tools-custom/performance/>
- <https://google.github.io/adk-docs/tools-custom/confirmation/>
- <https://google.github.io/adk-docs/tools-custom/authentication/>
- <https://google.github.io/adk-docs/tools/limitations/>

### 6) Session, State, Memory, Artifacts
These solve short-term and long-term context management.

- Session: per conversation/invocation context.
- State: structured mutable per-session data.
- Memory: persistent cross-session recall.
- Artifacts: binary or large outputs (evidence files, reports, media, etc.).

Read:
- <https://google.github.io/adk-docs/sessions/>
- <https://google.github.io/adk-docs/sessions/state/>
- <https://google.github.io/adk-docs/sessions/memory/>
- <https://google.github.io/adk-docs/artifacts/>

### 7) Events, Actions, and Control Hooks
- Events are internal units of runtime progress.
- Actions represent important state transitions/operations.
- Callbacks provide local interception points.
- Plugins provide broader/global interception and policy capabilities.

Read:
- <https://google.github.io/adk-docs/events/>
- <https://google.github.io/adk-docs/callbacks/>
- <https://google.github.io/adk-docs/callbacks/types-of-callbacks/>
- <https://google.github.io/adk-docs/plugins/>

### 8) App Layer
- `App` defines higher-level runtime behavior and composition.
- Useful for centralizing plugins, context strategy, and environment-specific setup.

Read:
- <https://google.github.io/adk-docs/apps/>

### 9) Context Management and Token Efficiency
- Context caching and compression reduce repeated prompt/token costs.
- Critical for long sessions and multi-step tool workflows.

Read:
- <https://google.github.io/adk-docs/context/caching/>

### 10) Interoperability Standards
- MCP: a protocol for tool ecosystem interoperability.
- A2A: agent-to-agent protocol interoperability.
- Grounding: retrieval/evidence-supported response quality.

Read:
- <https://google.github.io/adk-docs/mcp/>
- <https://google.github.io/adk-docs/a2a/>
- <https://google.github.io/adk-docs/grounding/>

### 11) Observability, Evaluation, and Safety
- Logging/telemetry for debugging and operations.
- Evaluation harnesses for trajectory and response quality.
- User simulation for scenario testing.
- Safety/guardrails for policy, risk, and action constraints.

Read:
- <https://google.github.io/adk-docs/observability/logging/>
- <https://google.github.io/adk-docs/evaluate/>
- <https://google.github.io/adk-docs/evaluate/criteria/>
- <https://google.github.io/adk-docs/evaluate/user-sim/>
- <https://google.github.io/adk-docs/safety/>

### 12) Deployment Paths
- Local/dev workflows (CLI/UI/API server).
- Cloud Run and GKE for self-managed deployment.
- Vertex AI Agent Engine for managed production execution.

Read:
- <https://google.github.io/adk-docs/deploy/>
- <https://google.github.io/adk-docs/deploy/cloud-run/>
- <https://google.github.io/adk-docs/deploy/gke/>
- <https://google.github.io/adk-docs/deploy/agent-engine/>

## Concept Dependency Graph (Practical Order)
Use this order to learn and design correctly:

1. Runtime primitives (`Runner`, `Event`, session services)
2. Agent patterns (`LlmAgent`, workflow agents, custom base agent)
3. Tooling (function/OpenAPI/MCP + confirmation/auth)
4. State/memory/artifact strategy
5. Callbacks/plugins guardrails and policy controls
6. Context optimization (cache/compression)
7. Evaluation/safety observability loops
8. Deployment topology and operational hardening

## Design Patterns You Should Reuse

### Pattern A: Specialist Multi-Agent Pipeline
- Perception/analysis/decision/action agents are split into separate responsibilities.
- A workflow agent coordinates deterministic stage order.
- Benefits: clearer debugging, easier policy enforcement, replaceable components.

### Pattern B: Agent + Tool Boundary Discipline
- Keep agents focused on reasoning and planning.
- Keep tools focused on deterministic side-effecting operations.
- Add confirmation/auth wrappers for high-impact actions.

### Pattern C: Session for Live Incident, Memory for Historic Signal
- Store incident-local context in session state.
- Write durable lessons/signatures to memory.
- Persist evidence in artifacts for audit and replay.

### Pattern D: Production Guardrail Stack
- Callback/plugin checks before and after sensitive operations.
- Structured logging + evaluation criteria per critical flow.
- Policy-driven rejection/confirmation for destructive actions.

## Common Failure Modes (and Fixes)
- Overloaded single agent.
  - Fix: split into specialized agents with explicit handoff rules.
- Prompt-only control for safety.
  - Fix: enforce checks in tools, callbacks, plugins, and auth layers.
- No explicit state schema.
  - Fix: define stable state keys/contracts for each stage.
- Unbounded context growth.
  - Fix: apply context caching/compression and prune transient state.
- No deployment parity.
  - Fix: validate runtime behavior from local -> staging -> production with the same test scenarios.

## Production Readiness Checklist
- Agent topology documented (`who does what`).
- Tooling classified by risk with confirmation/auth policies.
- Session and memory stores chosen and tested.
- Artifact persistence path defined for evidence.
- Callback/plugin guardrails implemented and covered by tests.
- Logging and tracing enabled with searchable metadata.
- Evaluation suite includes success, failure, and adversarial cases.
- Safety policies mapped to enforceable runtime checks.
- Deployment target selected with runbook and rollback path.

## Fast Learning Tracks

### Track 1: Build First Working Agent (fast)
1. Technical overview
2. LLM agent basics
3. Function tools
4. Runtime/API server
5. Logging

### Track 2: Multi-Agent SecOps Architecture
1. Workflow agents (sequential/parallel/loop)
2. Session/state/memory/artifacts
3. Callbacks/plugins
4. Evaluation + safety
5. Deployment (Cloud Run/GKE/Agent Engine)

### Track 3: Enterprise Interop
1. Models and auth
2. MCP + MCP tools
3. OpenAPI tools
4. A2A and grounding
5. Context optimization

## Link Library by Topic

### Getting Started
- <https://google.github.io/adk-docs/>
- <https://google.github.io/adk-docs/get-started/about/>
- <https://google.github.io/adk-docs/tutorials/coding-with-ai/>

### Agents
- <https://google.github.io/adk-docs/agents/>
- <https://google.github.io/adk-docs/agents/llm-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/sequential-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/parallel-agents/>
- <https://google.github.io/adk-docs/agents/workflow-agents/loop-agents/>
- <https://google.github.io/adk-docs/agents/config/>
- <https://google.github.io/adk-docs/agents/models/>

### Tools
- <https://google.github.io/adk-docs/tools-custom/>
- <https://google.github.io/adk-docs/tools-custom/function-tools/>
- <https://google.github.io/adk-docs/tools-custom/openapi-tools/>
- <https://google.github.io/adk-docs/tools-custom/mcp-tools/>
- <https://google.github.io/adk-docs/tools-custom/performance/>
- <https://google.github.io/adk-docs/tools-custom/confirmation/>
- <https://google.github.io/adk-docs/tools-custom/authentication/>
- <https://google.github.io/adk-docs/tools/limitations/>

### Runtime + Context
- <https://google.github.io/adk-docs/runtime/>
- <https://google.github.io/adk-docs/runtime/runconfig/>
- <https://google.github.io/adk-docs/runtime/resume/>
- <https://google.github.io/adk-docs/runtime/api-server/>
- <https://google.github.io/adk-docs/context/caching/>

### Data + State
- <https://google.github.io/adk-docs/sessions/>
- <https://google.github.io/adk-docs/sessions/state/>
- <https://google.github.io/adk-docs/sessions/memory/>
- <https://google.github.io/adk-docs/artifacts/>
- <https://google.github.io/adk-docs/events/>

### Extensibility + Protocols
- <https://google.github.io/adk-docs/callbacks/>
- <https://google.github.io/adk-docs/callbacks/types-of-callbacks/>
- <https://google.github.io/adk-docs/plugins/>
- <https://google.github.io/adk-docs/apps/>
- <https://google.github.io/adk-docs/mcp/>
- <https://google.github.io/adk-docs/a2a/>
- <https://google.github.io/adk-docs/grounding/>

### Quality + Production
- <https://google.github.io/adk-docs/observability/logging/>
- <https://google.github.io/adk-docs/evaluate/>
- <https://google.github.io/adk-docs/evaluate/criteria/>
- <https://google.github.io/adk-docs/evaluate/user-sim/>
- <https://google.github.io/adk-docs/safety/>
- <https://google.github.io/adk-docs/deploy/>
- <https://google.github.io/adk-docs/deploy/cloud-run/>
- <https://google.github.io/adk-docs/deploy/gke/>
- <https://google.github.io/adk-docs/deploy/agent-engine/>

## How to Use This in Future Threads
- Reference this file directly: `docs/adk_integration/adk_docs_knowledge_base.md`.
- Ask for updates by section (for example: “refresh tools/auth sections”).
- For implementation work, pair this with repo-specific architecture docs under `docs/architecture/`.

## Maintenance Note
When ADK docs change, re-check:
1. `llms-full.txt` for broad diffs,
2. deployment pages,
3. tooling/auth/limitations pages,
4. runtime and safety pages.

Then update this file with date + delta summary.
