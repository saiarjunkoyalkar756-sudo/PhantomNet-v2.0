import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.cognitive_core_intelligence.cognitive_core import CognitiveCore

class TestCognitiveMemoryIntegration(unittest.TestCase):

    def test_memory_learns_and_recalls_threat(self):
        """
        Tests that the CognitiveCore learns a new threat and recalls it from memory.
        """
        print("\n--- Running Test Scenario: Synthetic Cognitive Memory Integration ---")
        
        core = CognitiveCore()
        
        # 1. Analyze a new, unknown threat
        new_threat = "zero_day_exploit_variant_XYZ"
        print(f"\n--- First analysis of new threat: {new_threat} ---")
        first_analysis = core.analyze_threat(new_threat)
        
        # Verify it was treated as "low" risk initially
        self.assertEqual(first_analysis["threat_level"], "low")
        
        # 2. Manually "enrich" the analysis and update the memory (simulating an external process)
        first_analysis["threat_level"] = "critical"
        first_analysis["description"] = "Enriched Analysis: Confirmed zero-day exploit."
        core.memory.store_episode(new_threat, first_analysis, "Patched and isolated.")
        
        # 3. Analyze the same threat again
        print(f"\n--- Second analysis of same threat: {new_threat} ---")
        second_analysis = core.analyze_threat(new_threat)
        
        # 4. Verify that the core now recalls the enriched analysis from memory
        self.assertEqual(second_analysis["threat_level"], "critical")
        self.assertIn("Enriched Analysis", second_analysis["description"])
        print("\n--- Verification successful: Core recalled enriched analysis from memory. ---")

if __name__ == "__main__":
    unittest.main()
