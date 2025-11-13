import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.emotionally_aware_incident_assistant.incident_assistant import EmotionallyAwareIncidentAssistant

def run_assistant_test():
    """
    Tests the EmotionallyAwareIncidentAssistant's response generation.
    """
    print("--- Running Test Scenario: Emotionally-Aware Incident Assistant ---")
    
    assistant = EmotionallyAwareIncidentAssistant()
    
    scenarios = [
        {"level": "critical", "description": "Unauthorized root access detected."}, 
        {"level": "high", "description": "Multiple failed login attempts from a suspicious IP."}, 
        {"level": "medium", "description": "An unusual port scan was detected."}, 
        {"level": "low", "description": "A new device has connected to the guest network."} 
    ]
    
    for scenario in scenarios:
        print(f"\n--- Testing scenario: {scenario['level']} ---")
        response = assistant.generate_response(scenario["level"], scenario["description"])
        print(f"Tone: {response['tone']}")
        print(f"Urgency: {response['urgency']}")
        print(f"Response: {response['response_text']}")

if __name__ == "__main__":
    run_assistant_test()
