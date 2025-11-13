import sys
import os

# Add the parent directory to the Python path to allow for package-like imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.cognitive_core_intelligence.cognitive_core import CognitiveCore
from features.neural_security_language.nsl_parser import NSLParser

def run_test_scenario():
    """
    Tests the integration of CognitiveCore and NSLParser.
    """
    print("--- Running Test Scenario: Cognitive Core and NSL Integration ---")
    
    # 1. Initialize the core components
    core = CognitiveCore()
    parser = NSLParser()
    
    # 2. Simulate a threat detection
    threat = "suspicious login pattern detected"
    analysis_result = core.analyze_threat(threat)
    
    print(f"\n--- Threat Analysis Result ---")
    print(analysis_result)
    
    # 3. Based on the analysis, generate an NSL command
    if analysis_result["threat_level"] in ["medium", "high", "critical"]:
        nsl_command = 'trigger("auto_isolation").verify(with="behavioral_signatures")'
        print(f"\n--- Generated NSL Command ---")
        print(nsl_command)
        
        # 4. Parse the NSL command
        parsed_action = parser.parse_nsl_script(nsl_command)
        print(f"\n--- Parsed NSL Action ---")
        print(parsed_action)
        
        # 5. Execute the action with the Cognitive Core
        if parsed_action["status"] == "parsed":
            execution_result = core.execute_action(parsed_action)
            print(f"\n--- Action Execution Result ---")
            print(execution_result)
        else:
            print("\n--- Could not parse NSL command. ---")
    else:
        print("\n--- Threat level is low, no action required. ---")

if __name__ == "__main__":
    run_test_scenario()