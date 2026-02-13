from __future__ import annotations

from google.adk.agents import Agent
from shared.adk.observability import (
    after_model_callback,
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
)
from shared.adk.settings import default_model
from .prompts import DESCRIPTION, INSTRUCTION
from .tools import TOOLS


agent = Agent(
    name='anomaly_detector',
    description=DESCRIPTION,
    model=default_model(),
    instruction=INSTRUCTION,
    tools=TOOLS,
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    on_tool_error_callback=on_tool_error_callback,
    after_model_callback=after_model_callback,
)
