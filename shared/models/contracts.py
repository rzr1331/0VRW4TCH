from __future__ import annotations

from typing import List, Literal

from pydantic import BaseModel, Field


class KeySignal(BaseModel):
    metric_name: str
    latest_value: float | str
    unit: str | None = None
    source: Literal["live", "mock", "unknown"] = "unknown"


class RiskItem(BaseModel):
    risk_id: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    evidence: List[str] = Field(default_factory=list)


class RecommendedActionItem(BaseModel):
    action_id: str
    priority: Literal["p1", "p2", "p3", "p4"] = "p3"
    description: str
    owner: Literal["security", "ops", "platform", "compliance", "human"] = "ops"


class MonitoringScope(BaseModel):
    runtime_profile: Literal["host-process", "dockerized", "hybrid", "unknown"] = "unknown"
    monitored_entities: List[str] = Field(default_factory=list)
    missing_coverage: List[str] = Field(default_factory=list)


class SystemHealthReport(BaseModel):
    health_status: Literal["healthy", "degraded", "critical", "unknown"] = "unknown"
    discovered_assets: dict = Field(default_factory=dict)
    monitoring_scope: MonitoringScope = Field(default_factory=MonitoringScope)
    key_signals: List[KeySignal] = Field(default_factory=list)
    risks: List[RiskItem] = Field(default_factory=list)
    recommended_actions: List[RecommendedActionItem] = Field(default_factory=list)
    telemetry_source: Literal["live", "mock", "mixed", "unknown"] = "unknown"
    notes: List[str] = Field(default_factory=list)


class DelegationDecision(BaseModel):
    delegated_to: str
    reason: str
    expected_output: str


class RootAgentResponse(BaseModel):
    primary_decision: DelegationDecision
    supporting_delegations: List[DelegationDecision] = Field(default_factory=list)
    final_summary: str
    recommended_next_steps: List[str] = Field(default_factory=list)
