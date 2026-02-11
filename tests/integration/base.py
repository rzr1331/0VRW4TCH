"""
Base classes and utilities for scenario-based testing.

Each scenario test simulates receiving threat signals and observes
how the agents (Magistrate, Action Kamen, Thought) respond.
"""

import os
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Type
from datetime import datetime

# Ensure environment is loaded
from dotenv import load_dotenv
load_dotenv()


# =============================================================================
# SCENARIO REGISTRY - Import register_scenario from here in all scenarios!
# =============================================================================
SCENARIO_REGISTRY: Dict[str, Type["ScenarioTest"]] = {}


def register_scenario(cls: Type["ScenarioTest"]) -> Type["ScenarioTest"]:
    """
    Decorator to register a scenario test.
    
    Usage in scenario files:
        from tests.base import ScenarioTest, ThreatScenario, register_scenario
        
        @register_scenario
        class MyScenario(ScenarioTest):
            ...
    """
    SCENARIO_REGISTRY[cls.__name__] = cls
    return cls


@dataclass
class ThreatScenario:
    """
    Defines a threat scenario for testing.
    
    Attributes:
        name: Unique scenario identifier
        description: What this scenario tests
        threat_signals: Simulated signals from monitoring agents
        expected_severity: Expected severity classification
        expected_attack_type: Expected attack classification
        expected_actions: Actions that should be recommended
    """
    name: str
    description: str
    threat_signals: List[Dict[str, Any]]
    expected_severity: str = "high"
    expected_attack_type: Optional[str] = None
    expected_actions: List[str] = field(default_factory=list)
    

@dataclass
class ScenarioResult:
    """
    Result of running a scenario test.
    """
    scenario_name: str
    success: bool
    agent_response: str
    duration_seconds: float
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class ScenarioTest(ABC):
    """
    Base class for scenario tests.
    
    Subclass this to create new test scenarios.
    """
    
    @property
    @abstractmethod
    def scenario(self) -> ThreatScenario:
        """Return the threat scenario definition."""
        pass
    
    def get_initial_prompt(self) -> str:
        """
        Generate the initial prompt to send to Magistrate.
        
        Override this to customize how threat signals are presented.
        """
        signals_text = self._format_signals(self.scenario.threat_signals)
        
        return f"""
## Incoming Threat Signals

The following threat signals have been received from monitoring agents.
Analyze these signals, assess severity, classify the attack type, and 
recommend appropriate remediation actions.

{signals_text}

Please delegate this entire security incident to the 'security_magistrate' agent.

Tell the security_magistrate to:
1. Use analyze_threat_signals to correlate the signals
2. Use assess_severity to determine the severity level
3. Use classify_attack_type to identify the attack
4. Decide on recommended actions
5. If remediation is needed, delegate to security_enforcer (Action Kamen)
"""
    
    def _format_signals(self, signals: List[Dict[str, Any]]) -> str:
        """Format threat signals for the prompt."""
        formatted = []
        for i, signal in enumerate(signals, 1):
            formatted.append(f"### Signal {i}")
            formatted.append(f"- **Source**: {signal.get('source', 'unknown')}")
            formatted.append(f"- **Type**: {signal.get('signal_type', 'unknown')}")
            formatted.append(f"- **Description**: {signal.get('description', 'N/A')}")
            if signal.get('affected_systems'):
                formatted.append(f"- **Affected Systems**: {', '.join(signal['affected_systems'])}")
            if signal.get('indicators'):
                formatted.append(f"- **Indicators**: {signal['indicators']}")
            formatted.append("")
        return "\n".join(formatted)
    
    def validate_response(self, response: str) -> Dict[str, Any]:
        """
        Validate the agent's response.
        
        Override this to add custom validation logic.
        
        Returns:
            Dict with 'valid' bool and 'issues' list
        """
        issues = []
        
        # Check if severity was assessed
        severity_keywords = ['critical', 'high', 'medium', 'low']
        if not any(kw in response.lower() for kw in severity_keywords):
            issues.append("No severity assessment found in response")
        
        # Check if attack type was identified
        if self.scenario.expected_attack_type:
            if self.scenario.expected_attack_type.lower() not in response.lower():
                issues.append(f"Expected attack type '{self.scenario.expected_attack_type}' not found")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
        }


async def run_scenario(test: ScenarioTest, verbose: bool = True) -> ScenarioResult:
    """
    Run a single scenario test.
    
    Args:
        test: The scenario test to run
        verbose: Whether to print progress
        
    Returns:
        ScenarioResult with test outcome
    """
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types
    from agents.root_agent import root_agent
    
    scenario = test.scenario
    start_time = datetime.now()
    
    if verbose:
        print(f"\n{'='*60}")
        print(f"🧪 Running Scenario: {scenario.name}")
        print(f"📝 {scenario.description}")
        print(f"{'='*60}\n")
    
    try:
        # Create session service and runner
        session_service = InMemorySessionService()
        runner = Runner(
            agent=root_agent,
            app_name="security_agents_test",
            session_service=session_service,
        )
        
        # Create a new session
        session = await session_service.create_session(
            app_name="security_agents_test",
            user_id="test_user",
        )
        
        # Get the initial prompt and wrap in Content object
        prompt_text = test.get_initial_prompt()
        message = types.Content(
            role="user",
            parts=[types.Part(text=prompt_text)]
        )
        
        if verbose:
            print("📨 Sending threat signals to Magistrate...\n")
        
        # Run the agent
        full_response = ""
        current_agent = "Magistrate"
        
        # Colors and formatting
        BLUE = "\033[94m"
        RED = "\033[91m" 
        YELLOW = "\033[93m"
        GREEN = "\033[92m"
        RESET = "\033[0m"
        BOLD = "\033[1m"
        
        def print_box(title, content, color):
            print(f"\n{color}╭── {BOLD}{title}{RESET}{color} {'─'*(70-len(title))}╮{RESET}")
            for line in content.strip().split('\n'):
                print(f"{color}│{RESET} {line:<72} {color}│{RESET}")
            print(f"{color}╰{'─'*74}╯{RESET}")

        async for event in runner.run_async(
            user_id="test_user",
            session_id=session.id,
            new_message=message,
        ):
            # Iterate through all parts in the event content
            if hasattr(event, 'content') and event.content and event.content.parts:
                for part in event.content.parts:
                    
                    # 1. Handle Text (Thoughts)
                    if hasattr(part, 'text') and part.text:
                        text = part.text
                        full_response += text
                        
                        # Detect agent switch
                        if "Action Kamen" in text:
                            current_agent = "Action Kamen"
                            color = RED
                        elif "Magistrate" in text: # Optional refinement
                            current_agent = "Magistrate" 
                            color = BLUE
                        else:
                            # Keep current color
                            pass 
                            
                        print(f"{color}{text}{RESET}", end="", flush=True)

                    # 2. Handle Function Calls (Commands)
                    if hasattr(part, 'function_call') and part.function_call:
                        fc = part.function_call
                        title = f"🛠️  CMD: {fc.name}"
                        # args might be a dict or object, handle cleanly
                        args = fc.args if hasattr(fc, 'args') else "N/A"
                        print_box(title, str(args), YELLOW)

                    # 3. Handle Function Responses (Outputs)
                    if hasattr(part, 'function_response') and part.function_response:
                        fr = part.function_response
                        title = f"📤 OUTPUT: {fr.name}"
                        # response content
                        content = str(fr.response) if hasattr(fr, 'response') else "No output"
                        print_box(title, content, GREEN)
        
        if verbose:
            print("\n")
        
        # Validate the response
        validation = test.validate_response(full_response)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        if verbose:
            if validation['valid']:
                print(f"✅ Scenario PASSED in {duration:.2f}s")
            else:
                print(f"❌ Scenario FAILED in {duration:.2f}s")
                for issue in validation['issues']:
                    print(f"   - {issue}")
        
        return ScenarioResult(
            scenario_name=scenario.name,
            success=validation['valid'],
            agent_response=full_response,
            duration_seconds=duration,
            details=validation,
        )
        
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        if verbose:
            print(f"💥 Scenario ERROR: {str(e)}")
        
        return ScenarioResult(
            scenario_name=scenario.name,
            success=False,
            agent_response="",
            duration_seconds=duration,
            error=str(e),
        )
