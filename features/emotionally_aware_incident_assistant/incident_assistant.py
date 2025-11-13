class EmotionallyAwareIncidentAssistant:
    """
    An empathetic AI persona that guides users during incidents.
    Uses tone modulation, urgency scoring, and context awareness.
    """
    def __init__(self):
        print("Initializing Emotionally-Aware Incident Assistant...")
        self.urgency_scores = {
            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0
        }

    def generate_response(self, threat_level: str, threat_description: str):
        """
        Generates a user-facing response based on the threat level and description.
        """
        urgency = self.urgency_scores.get(threat_level, 0.1)
        
        if urgency > 0.7:
            tone = "urgent"
            response = f"CRITICAL ALERT: {threat_description} I am initiating immediate countermeasures."
        elif urgency > 0.4:
            tone = "concerned"
            response = f"Warning: {threat_description} I am monitoring the situation closely."
        else:
            tone = "calm"
            response = f"FYI: {threat_description} This is a low-level event, but I am logging it for future reference."
            
        return {
            "tone": tone,
            "urgency": urgency,
            "response_text": response
        }