"""
Test that the ADK pipeline structure is correctly assembled.

Validates the SequentialAgent → ParallelAgent → Agent hierarchy,
output_key assignments, and sub-agent wiring after the pipeline refactor.
"""
from google.adk.agents import SequentialAgent, ParallelAgent, LlmAgent


def _load_pipeline():
    """Import the pipeline (may be slow due to model init, so isolate it)."""
    from agents.stages import secops_pipeline
    return secops_pipeline


class TestPipelineStructure:
    """Verify the pipeline topology matches the design."""

    def test_root_is_sequential_agent(self):
        root = _load_pipeline()
        assert isinstance(root, SequentialAgent), f"Expected SequentialAgent, got {type(root).__name__}"
        assert root.name == "secops_pipeline"

    def test_root_has_three_stages(self):
        root = _load_pipeline()
        assert len(root.sub_agents) == 3, f"Expected 3 stages, got {len(root.sub_agents)}"

    def test_stage_names(self):
        root = _load_pipeline()
        names = [sa.name for sa in root.sub_agents]
        assert names == [
            "perception_stage",
            "analysis_stage",
            "security_magistrate",
        ]

    def test_perception_is_parallel(self):
        root = _load_pipeline()
        perception = root.sub_agents[0]
        assert isinstance(perception, ParallelAgent)
        child_names = [a.name for a in perception.sub_agents]
        assert "scope_scanner" in child_names
        assert "system_health" in child_names

    def test_analysis_is_parallel(self):
        root = _load_pipeline()
        analysis = root.sub_agents[1]
        assert isinstance(analysis, ParallelAgent)
        child_names = [a.name for a in analysis.sub_agents]
        assert "anomaly_detector" in child_names
        assert "vulnerability_assessor" in child_names

    def test_magistrate_has_sub_agents(self):
        root = _load_pipeline()
        mag = root.sub_agents[2]
        assert isinstance(mag, LlmAgent)
        assert mag.output_key == "decision_verdict"
        sub_names = [sa.name for sa in mag.sub_agents]
        assert "thought" in sub_names
        assert "security_enforcer" in sub_names

    def test_perception_agents_have_output_keys(self):
        root = _load_pipeline()
        perception = root.sub_agents[0]
        keys = {a.name: a.output_key for a in perception.sub_agents}
        assert keys["scope_scanner"] == "perception_scope"
        assert keys["system_health"] == "perception_health"

    def test_analysis_agents_have_output_keys(self):
        root = _load_pipeline()
        analysis = root.sub_agents[1]
        keys = {a.name: a.output_key for a in analysis.sub_agents}
        assert keys["anomaly_detector"] == "analysis_anomalies"
        assert keys["vulnerability_assessor"] == "analysis_vulnerabilities"

    def test_enforcer_has_output_key(self):
        root = _load_pipeline()
        mag = root.sub_agents[2]
        enforcer = next(a for a in mag.sub_agents if a.name == "security_enforcer")
        assert enforcer.output_key == "enforcement_result"
