"""
Runtime and deployment configuration for the SecOps platform.

Reads from environment variables with sensible defaults.
All model selection, provider config, and deployment knobs live here.

For domain constants (severity weights, attack types), see config.constants.
For secrets and API keys, see .env.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from dotenv import load_dotenv

load_dotenv()


# =============================================================================
# MODEL CONFIGURATION
# =============================================================================

# Model provider: "zai" (Z.AI GLM via LiteLLM) or "gemini"
MODEL_PROVIDER: str = os.getenv("MODEL_PROVIDER", "zai")

# Default model — used by all agents unless overridden per-agent below
DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "zai/glm-4.5")

# Per-agent model overrides (optional)
AGENT_MODELS: dict[str, str] = {
    "scope_scanner": os.getenv("MODEL_SCOPE_SCANNER", DEFAULT_MODEL),
    "system_health": os.getenv("MODEL_SYSTEM_HEALTH", DEFAULT_MODEL),
    "anomaly_detector": os.getenv("MODEL_ANOMALY_DETECTOR", DEFAULT_MODEL),
    "vulnerability_assessor": os.getenv("MODEL_VULNERABILITY_ASSESSOR", DEFAULT_MODEL),
    "magistrate": os.getenv("MODEL_MAGISTRATE", DEFAULT_MODEL),
    "thought": os.getenv("MODEL_THOUGHT", DEFAULT_MODEL),
    "action_kamen": os.getenv("MODEL_ACTION_KAMEN", DEFAULT_MODEL),
}


# =============================================================================
# MOCK MODE
# =============================================================================

MOCK_MODE: bool = os.getenv("MOCK_MODE", "false").lower() == "true"
MOCK_DELAY_SECONDS: float = float(os.getenv("MOCK_DELAY_SECONDS", "0.5"))


# =============================================================================
# APPLICATION IDENTITY
# =============================================================================

def app_name() -> str:
    """Application name used by ADK Runner."""
    return os.getenv("ADK_APP_NAME", "0VERW4TCH") or "0VERW4TCH"


# =============================================================================
# LOGGING
# =============================================================================

LOG_LEVEL: str = os.getenv("SECURITY_AGENTS_LOG_LEVEL", "INFO")


# =============================================================================
# MODEL FACTORY
# =============================================================================

def get_model_for_agent(agent_name: str) -> Any:
    """Return a model instance for the given agent.

    For ZAI provider, returns a LiteLlm wrapper.
    For Gemini provider, returns the model name string (ADK resolves it).
    """
    model_name = AGENT_MODELS.get(agent_name.lower(), DEFAULT_MODEL)

    if MODEL_PROVIDER == "zai":
        from google.adk.models.lite_llm import LiteLlm

        return LiteLlm(
            model=model_name,
            api_key=os.getenv("ZAI_API_KEY"),
            litellm_params={
                "max_parallel_requests": 5,
                "tpm_limit": 5000,
                "rpm_limit": 40,
            },
        )

    # Gemini models use string directly
    return model_name
