from __future__ import annotations

from google.adk.agents import Agent
from shared.adk.observability import (
    after_model_callback,
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
)
from config.settings import get_model_for_agent
from .prompts import DESCRIPTION, INSTRUCTION
from .tools import TOOLS


agent = Agent(
    name='anomaly_detector',
    description=DESCRIPTION,
    model=get_model_for_agent("anomaly_detector"),
    instruction=INSTRUCTION,
    tools=TOOLS,
    output_key="analysis_anomalies",
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    on_tool_error_callback=on_tool_error_callback,
    after_model_callback=after_model_callback,
)
