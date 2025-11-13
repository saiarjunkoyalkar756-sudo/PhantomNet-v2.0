import time
import threading

class EdgeBrain:
    """
    Lightweight OS agent that runs on IoT, mobile, and server nodes.
    Each node contributes insights to a shared AI fabric.
    """
    def __init__(self, orchestrator):
        self.node_id = "node_" + str(int(time.time()))
        self.orchestrator = orchestrator
        self.is_running = False
        print(f"Initializing Edge Brain for node: {self.node_id}")

    def register_with_core(self):
        """
        Simulates registering the edge node with the central cognitive core.
        """
        print(f"Node {self.node_id} registering with core...")
        print("Registration successful.")

    def collect_telemetry(self):
        """
        Simulates collecting system telemetry and sends it to the orchestrator.
        """
        while self.is_running:
            telemetry_data = {
                "node_id": self.node_id,
                "cpu_usage": round(time.time() % 100, 2),
                "active_connections": int(time.time() % 50)
            }
            print(f"Collected telemetry: {telemetry_data}")
            self.orchestrator.receive_telemetry(telemetry_data)
            time.sleep(10)

    def start(self):
        """
        Starts the Edge Brain's telemetry collection.
        """
        self.is_running = True
        self.register_with_core()
        telemetry_thread = threading.Thread(target=self.collect_telemetry)
        telemetry_thread.daemon = True
        telemetry_thread.start()
        print(f"Edge Brain {self.node_id} started.")

    def stop(self):
        """
        Stops the Edge Brain's telemetry collection.
        """
        self.is_running = False
        print(f"Edge Brain {self.node_id} stopped.")
