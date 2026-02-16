"""
Root agent for the 0VRW4TCH SecOps platform.

This module preserves backward-compatibility: importing ``root_agent`` from
``agents`` still works, but now it points to the deterministic SequentialAgent
pipeline defined in ``agents.stages``.

The old LLM-delegated flat Agent is replaced by the pipeline:
  SequentialAgent
    ├── ParallelAgent  (perception_stage)
    │     ├── scope_scanner
    │     └── system_health
    ├── ParallelAgent  (analysis_stage)
    │     ├── anomaly_detector
    │     └── vulnerability_assessor
    └── Agent          (security_magistrate)
          ├── thought_agent
          └── security_enforcer
"""
from __future__ import annotations

from agents.stages import secops_pipeline

# Backward-compatible alias — ``root_agent`` is the pipeline entrypoint.
root_agent = secops_pipeline
