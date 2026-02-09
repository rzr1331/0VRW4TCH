"""
Test Runner - Execute scenario tests.

Usage:
    python -m tests.runner
    python -m tests.runner --scenario cryptomining
    python -m tests.runner --list
"""

import os
import sys
import asyncio
import argparse
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from tests.integration.base import ScenarioTest, ScenarioResult, run_scenario, SCENARIO_REGISTRY


def discover_scenarios():
    """Discover and import all scenario modules."""
    # Import scenarios to trigger @register_scenario decorators
    # import tests.integration.scenarios.cryptomining
    # import tests.integration.scenarios.ransomware
    # import tests.integration.scenarios.data_exfiltration
    # import tests.integration.scenarios.credential_theft
    import tests.integration.scenarios.container_escape


async def run_all_scenarios(verbose: bool = True):
    """Run all registered scenario tests."""
    results = []
    
    print("\n" + "="*60)
    print("🔬 SECURITY AGENTS - SCENARIO TESTS")
    print("="*60)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📊 Running {len(SCENARIO_REGISTRY)} scenarios\n")
    
    for name, cls in SCENARIO_REGISTRY.items():
        test = cls()
        result = await run_scenario(test, verbose=verbose)
        results.append(result)
    
    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    
    passed = sum(1 for r in results if r.success)
    failed = len(results) - passed
    total_time = sum(r.duration_seconds for r in results)
    
    for result in results:
        status = "✅ PASS" if result.success else "❌ FAIL"
        print(f"  {status} | {result.scenario_name} ({result.duration_seconds:.2f}s)")
    
    print(f"\n  Total: {passed}/{len(results)} passed in {total_time:.2f}s")
    
    if failed > 0:
        print(f"  ⚠️  {failed} scenario(s) failed")
    else:
        print("  🎉 All scenarios passed!")
    
    return results


async def run_single_scenario(scenario_name: str, verbose: bool = True):
    """Run a single scenario by name."""
    matching = None
    for name, cls in SCENARIO_REGISTRY.items():
        test = cls()
        if scenario_name.lower() in test.scenario.name.lower():
            matching = test
            break
    
    if not matching:
        print(f"❌ Scenario '{scenario_name}' not found")
        print("\nAvailable scenarios:")
        for name, cls in SCENARIO_REGISTRY.items():
            test = cls()
            print(f"  - {test.scenario.name}: {test.scenario.description}")
        sys.exit(1)
    
    return await run_scenario(matching, verbose=verbose)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run security agent scenario tests")
    parser.add_argument("--scenario", "-s", help="Run specific scenario")
    parser.add_argument("--list", "-l", action="store_true", help="List available scenarios")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    
    args = parser.parse_args()
    
    # Discover scenarios first
    discover_scenarios()
    
    if args.list:
        print("\n📋 Available Scenarios:\n")
        for name, cls in SCENARIO_REGISTRY.items():
            test = cls()
            print(f"  - {test.scenario.name}: {test.scenario.description}")
        return
    
    # Check for API key
    if not os.getenv("ZAI_API_KEY"):
        print("❌ Error: ZAI_API_KEY environment variable not set")
        print("   Export your key: export ZAI_API_KEY=your_key_here")
        sys.exit(1)
    
    verbose = not args.quiet
    
    if args.scenario:
        asyncio.run(run_single_scenario(args.scenario, verbose=verbose))
    else:
        asyncio.run(run_all_scenarios(verbose=verbose))


if __name__ == "__main__":
    main()
