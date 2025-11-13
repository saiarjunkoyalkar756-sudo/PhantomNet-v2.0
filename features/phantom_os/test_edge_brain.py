import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.phantom_os.edge_brain import EdgeBrain

def run_edge_brain_test():
    """
    Tests the EdgeBrain's basic functionality.
    """
    print("--- Running Test Scenario: PhantomOS - The Edge Brain ---")
    
    # The core network endpoint would be a real address in a production system
    core_endpoint = "tcp://127.0.0.1:5555"
    
    edge_agent = EdgeBrain(core_network_endpoint=core_endpoint)
    edge_agent.start()
    
    print("\n--- Edge Brain is running. Will stop in 25 seconds. ---")
    try:
        # Let the agent run for a bit to collect some telemetry
        time.sleep(25)
    except KeyboardInterrupt:
        print("\n--- Test interrupted by user. ---")
    finally:
        edge_agent.stop()
        print("\n--- Test finished. ---")

if __name__ == "__main__":
    run_edge_brain_test()
