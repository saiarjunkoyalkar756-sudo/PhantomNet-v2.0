import os
import importlib
from .analyzers.base import Analyzer

ANALYZERS = []

def load_analyzers():
    analyzers_dir = os.path.join(os.path.dirname(__file__), "analyzers")
    for filename in os.listdir(analyzers_dir):
        if filename.endswith(".py") and filename != "base.py" and not filename.startswith("__"):
            module_name = f"phantomnet_agent.analyzers.{filename[:-3]}"
            module = importlib.import_module(module_name)
            for item in dir(module):
                obj = getattr(module, item)
                if isinstance(obj, type) and issubclass(obj, Analyzer) and obj is not Analyzer:
                    ANALYZERS.append(obj())

load_analyzers()

def analyze_attack(payload):
    all_attack_types = set()
    for analyzer in ANALYZERS:
        result = analyzer.analyze(payload)
        if result:
            # If the analyzer returns a comma-separated string, split it
            for attack_type in result.split(', '):
                all_attack_types.add(attack_type.strip())
    
    if not all_attack_types:
        return "Unknown"
    
    return ", ".join(sorted(list(all_attack_types)))
