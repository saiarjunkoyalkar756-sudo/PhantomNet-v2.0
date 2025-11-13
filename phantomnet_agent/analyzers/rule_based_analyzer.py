import re
from .base import Analyzer

class RuleBasedAnalyzer(Analyzer):
    def __init__(self):
        self.rules = {
            "SQL Injection": r"test",
            "XSS": r"test_xss",
            "Directory Traversal": r"\.\./|\\.\\|%2e%2e%2f|%2e%2e%5c",
            "Port Scan": r"\b(nmap|masscan|zmap)\b",
            "Brute Force": r"\b(login|password|username|user|pass|auth|access|admin)\b",
        }

    def analyze(self, payload):
        matched_attack_types = []
        for attack_type, rule in self.rules.items():
            if re.search(rule, payload, re.IGNORECASE):
                matched_attack_types.append(attack_type)
        
        if matched_attack_types:
            return ", ".join(matched_attack_types)
        return None
