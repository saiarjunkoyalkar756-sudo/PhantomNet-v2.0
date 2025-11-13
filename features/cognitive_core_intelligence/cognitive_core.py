from features.synthetic_cognitive_memory.cognitive_memory import CognitiveMemory

from features.synthetic_cognitive_memory.cognitive_memory import CognitiveMemory

class CognitiveCore:
    """
    Cognitive Core Intelligence: Blends symbolic logic and deep neural reasoning
    for context-aware threat analysis.
    """
    def __init__(self, cognitive_memory):
        self.known_threats = {
            "malware_signature_A": {"level": "critical", "description": "Known sophisticated malware variant."},
            "phishing_attempt_B": {"level": "high", "description": "Attempted phishing attack from a blacklisted IP."},
            "port_scan_C": {"level": "medium", "description": "Suspicious port scanning activity."},
            "unauthorized_access_D": {"level": "critical", "description": "Confirmed unauthorized access attempt."},
            "ddos_attack_E": {"level": "critical", "description": "Distributed Denial of Service attack in progress."}
        }
        self.memory = cognitive_memory
        print("Initializing Cognitive Core with shared Cognitive Memory...")

    def analyze_threat(self, threat_data):
        """
        Analyzes threat data using cognitive core intelligence and memory.
        Can handle string-based threats or dictionary-based telemetry data.
        """
        print(f"Analyzing threat: {threat_data}")

        # Handle dictionary-based telemetry data
        if isinstance(threat_data, dict):
            if threat_data.get("cpu_usage", 0) > 90.0:
                analysis_result = {
                    "status": "analyzed",
                    "threat_level": "high",
                    "description": f"High CPU usage detected on node {threat_data.get('node_id')}.",
                    "threat_data_received": threat_data
                }
                self.memory.store_episode(str(threat_data), analysis_result, "Logged for performance review.")
                return analysis_result

        # Fallback to string-based analysis for other threat types
        threat_str = str(threat_data)
        recalled_episode = self.memory.recall_episode(threat_str)
        if recalled_episode:
            print("Threat recognized from cognitive memory.")
            return recalled_episode["analysis"]

        threat_info = self.known_threats.get(threat_str)
        
        if threat_info:
            status = "analyzed"
            threat_level = threat_info["level"]
            description = threat_info["description"]
        elif "suspicious" in threat_str.lower():
            status = "analyzed"
            threat_level = "medium"
            description = "Suspicious activity detected based on behavioral analysis."
        else:
            status = "analyzed"
            threat_level = "low"
            description = "Unknown threat, further investigation recommended."

        analysis_result = {"status": status, "threat_level": threat_level, "description": description, "threat_data_received": threat_str}
        
        self.memory.store_episode(threat_str, analysis_result, "Logged for future analysis.")
        
        return analysis_result

    def execute_action(self, action: dict):
        """
        Executes a parsed action from the NSL parser.
        """
        print(f"Executing action: {action}")
        if action.get("intent") == "auto_isolation_trigger":
            print("--- ACTION: Auto-isolation protocol initiated.")
            print(f"--- REASON: Verification with {action.get('details')}")
            return {"status": "executed", "action": "auto_isolation"}
        else:
            print("--- ACTION: Unknown action.")
            return {"status": "failed", "reason": "Unknown action"}
