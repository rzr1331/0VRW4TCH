# ADK Implementation Notes

This repository now uses Google ADK as the primary runtime. The focus is on aligning agent behavior, tooling, and guardrails with ADK primitives.

## Key mappings
- Orchestration uses `Runner` and `SessionService`
- Agent-to-agent delegation uses sub-agents and `TransferToAgentTool`
- Tool calls are standard ADK tools with policy checks in the tool wrappers
- Session state should be used for traceable incident context

## Reference knowledge base
- Cross-thread ADK concept and links reference: `docs/adk_integration/adk_docs_knowledge_base.md`

## Next steps
- Introduce persistent session storage (PostgreSQL or Redis)
- Configure Vertex AI Memory Bank for persistent long-term recall
- Add artifacts for evidence collection and forensic payloads
- Implement guardrail callbacks for destructive actions
