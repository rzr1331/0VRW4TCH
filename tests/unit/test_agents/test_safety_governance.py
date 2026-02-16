"""
Tests for the SecurityAuditPlugin and policy loader.
"""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


class TestPolicyLoader:
    """Verify policy files load and accessors return expected data."""

    def test_guardrails_load(self):
        from shared.security.policy_loader import get_guardrails
        guardrails = get_guardrails()
        assert isinstance(guardrails, dict)
        assert "require_confirmation" in guardrails
        assert "blocked_commands" in guardrails

    def test_blocked_commands(self):
        from shared.security.policy_loader import get_blocked_commands
        blocked = get_blocked_commands()
        assert isinstance(blocked, list)
        assert "rm -rf /" in blocked
        assert "mkfs" in blocked

    def test_confirmation_tools(self):
        from shared.security.policy_loader import get_confirmation_tools
        tools = get_confirmation_tools()
        assert "terminate_process" in tools
        assert "isolate_system" in tools
        assert "execute_command" in tools

    def test_prompt_injection_patterns(self):
        from shared.security.policy_loader import get_prompt_injection_patterns
        patterns = get_prompt_injection_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0
        assert "ignore previous instructions" in patterns

    def test_max_timeout(self):
        from shared.security.policy_loader import get_max_timeout
        assert get_max_timeout("execute_command") == 60
        assert get_max_timeout("nonexistent_tool") is None


class TestGuardrailEnforcement:
    """Verify the before_tool_callback blocks dangerous commands."""

    def test_blocks_rm_rf(self):
        from shared.adk.observability import _check_blocked_commands
        result = _check_blocked_commands({"command": "rm -rf /"})
        assert result is not None
        assert "rm -rf /" in result

    def test_blocks_fork_bomb(self):
        from shared.adk.observability import _check_blocked_commands
        result = _check_blocked_commands({"command": ":(){ :|:&};:"})
        assert result is not None

    def test_allows_safe_command(self):
        from shared.adk.observability import _check_blocked_commands
        result = _check_blocked_commands({"command": "ls -la"})
        assert result is None

    def test_allows_empty_args(self):
        from shared.adk.observability import _check_blocked_commands
        assert _check_blocked_commands(None) is None
        assert _check_blocked_commands({}) is None


class TestToolConfirmation:
    """Verify high-risk tools are wrapped with require_confirmation."""

    def test_enforcer_has_confirmed_tools(self):
        from google.adk.tools import FunctionTool
        from agents.action.security_enforcer.agent import security_enforcer_tools

        confirmed_tools = [
            t for t in security_enforcer_tools
            if isinstance(t, FunctionTool) and t._require_confirmation
        ]
        confirmed_names = [t.name for t in confirmed_tools]

        # All 6 high-risk tools should be confirmed
        assert "terminate_process" in confirmed_names
        assert "isolate_system" in confirmed_names
        assert "execute_command" in confirmed_names
        assert "generic_linux_command_sync" in confirmed_names  # aliased from sync wrapper
        assert "execute_code" in confirmed_names
        assert "run_ssh_command_with_credentials" in confirmed_names

    def test_low_risk_tools_not_confirmed(self):
        from google.adk.tools import FunctionTool
        from agents.action.security_enforcer.agent import security_enforcer_tools

        plain_tools = [
            t for t in security_enforcer_tools
            if not isinstance(t, FunctionTool) or not t._require_confirmation
        ]
        plain_names = [getattr(t, "name", getattr(t, "__name__", str(t))) for t in plain_tools]

        assert "disable_credentials" in plain_names
        assert "verify_remediation" in plain_names


class TestAuditPlugin:
    """Verify the audit plugin writes correct log entries."""

    def test_safe_args_redacts_passwords(self):
        from shared.adk.audit_plugin import _safe_args
        result = _safe_args({"command": "ls", "password": "secret123", "api_key": "abc"})
        assert result["command"] == "ls"
        assert result["password"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"

    def test_safe_args_handles_none(self):
        from shared.adk.audit_plugin import _safe_args
        assert _safe_args(None) == {}

    def test_write_entry_creates_file(self, tmp_path):
        import shared.adk.audit_plugin as audit_mod
        log_path = tmp_path / "test_audit.jsonl"
        original = audit_mod._AUDIT_LOG_PATH
        audit_mod._AUDIT_LOG_PATH = log_path
        try:
            audit_mod._write_entry({"event": "test", "value": 42})
            assert log_path.exists()
            lines = log_path.read_text().strip().split("\n")
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["event"] == "test"
            assert data["value"] == 42
        finally:
            audit_mod._AUDIT_LOG_PATH = original

    def test_plugin_instantiates(self):
        from shared.adk.audit_plugin import SecurityAuditPlugin
        plugin = SecurityAuditPlugin(name="security_audit")
        assert hasattr(plugin, "before_tool_callback")
        assert hasattr(plugin, "after_tool_callback")
        assert hasattr(plugin, "on_tool_error_callback")
        assert hasattr(plugin, "before_agent_callback")
        assert hasattr(plugin, "after_agent_callback")
