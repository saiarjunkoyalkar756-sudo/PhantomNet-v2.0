import sys
import os
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.invisible_security_experience.seamless_defense import SeamlessDefense
from features.cognitive_core_intelligence.cognitive_core import CognitiveCore

def run_seamless_defense_test():
    """
    Tests the SeamlessDefense's basic functionality.
    """
    print("--- Running Test Scenario: Invisible Security Experience ---")
    
    core = CognitiveCore()
    seamless_defense = SeamlessDefense(cognitive_core=core)
    
    # Run the harmony monitor in a separate thread so we can stop it
    monitor_thread = threading.Thread(target=seamless_defense.monitor_system_harmony)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    print("\n--- Seamless Defense is running. Will stop in 40 seconds. ---")
    try:
        # Let the monitor run for a bit
        time.sleep(40)
    except KeyboardInterrupt:
        print("\n--- Test interrupted by user. ---")
    finally:
        print("\n--- Test finished. ---")

if __name__ == "__main__":
    run_seamless_defense_test()
