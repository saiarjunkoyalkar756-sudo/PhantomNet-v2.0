import re

class NSLParser:
    """
    Neural Security Language (NSL): Develops a natural, AI-readable scripting
    language for cybersecurity intent.
    """
    def __init__(self):
        print("Initializing Neural Security Language (NSL) Parser...")

    def parse_nsl_script(self, script):
        """
        Parses an NSL script and returns its interpreted intent.
        Example: trigger("auto_isolation").verify(with="behavioral_signatures")
        """
        print(f"Parsing NSL script: {script}")
        
        # Regex to extract the trigger and verification parts
        match = re.match(r'trigger\("(?P<trigger_action>.*?)"\)\.verify\(with="(?P<verify_with>.*?)"\)', script)
        
        if match:
            action = match.group("trigger_action")
            verification = match.group("verify_with")
            
            if action == "auto_isolation":
                return {
                    "status": "parsed",
                    "intent": "auto_isolation_trigger",
                    "details": f"Verification with {verification}"
                }

        return {"status": "failed", "intent": "unknown_intent"}
