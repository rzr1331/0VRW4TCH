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
    name='scope_scanner',
    description=DESCRIPTION,
    model=get_model_for_agent("scope_scanner"),
    instruction=INSTRUCTION,
    tools=TOOLS,
    output_key="perception_scope",
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    on_tool_error_callback=on_tool_error_callback,
    after_model_callback=after_model_callback,
)
