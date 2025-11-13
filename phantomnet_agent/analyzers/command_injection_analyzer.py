import re
from .base import Analyzer

class CommandInjectionAnalyzer(Analyzer):
    def __init__(self):
        # Common command injection patterns
        self.patterns = [
            r";\s*(ls|dir|cat|whoami|uname|ifconfig|ipconfig)",
            r"\|\|\s*(ls|dir|cat|whoami|uname|ifconfig|ipconfig)",
            r"&&\s*(ls|dir|cat|whoami|uname|ifconfig|ipconfig)",
            r"`\s*(ls|dir|cat|whoami|uname|ifconfig|ipconfig)\s*`",
            r"\$\(\s*(ls|dir|cat|whoami|uname|ifconfig|ipconfig)\s*\)",
        ]

    def analyze(self, payload):
        for pattern in self.patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return "Command Injection"
        return None
