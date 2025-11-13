import random
import time

class RedTeamAgent:
    def __init__(self, name="RedAgent"):
        self.name = name
        self.attack_actions = ["scan_port", "brute_force_ssh", "exploit_vulnerability", "phishing_attempt"]

    def generate_action(self, current_state: dict) -> str:
        """
        Simulates a red-team agent generating an attack action.
        In a real scenario, this would be a GAN-based AI generating sophisticated attacks.
        """
        print(f"[{self.name}] Analyzing state: {current_state}")
        action = random.choice(self.attack_actions)
        print(f"[{self.name}] Generated action: {action}")
        return action

class BlueTeamAgent:
    def __init__(self, name="BlueAgent"):
        self.name = name
        self.defense_actions = ["block_ip", "patch_vulnerability", "deploy_honeypot", "monitor_traffic"]

    def generate_action(self, current_state: dict, red_action: str) -> str:
        """
        Simulates a blue-team RL agent generating a counter-action.
        In a real scenario, this would be an RL agent learning optimal defenses.
        """
        print(f"[{self.name}] Red action observed: {red_action}. Analyzing state: {current_state}")
        
        # Simple reactive defense for placeholder
        if "brute_force_ssh" in red_action:
            action = "block_ip"
        elif "exploit_vulnerability" in red_action:
            action = "patch_vulnerability"
        else:
            action = random.choice(self.defense_actions)
        
        print(f"[{self.name}] Generated counter-action: {action}")
        return action

class SimulationEnvironment:
    def __init__(self):
        self.current_state = {"network_status": "normal", "honeypot_health": "good", "alerts": []}
        self.red_agent = RedTeamAgent()
        self.blue_agent = BlueTeamAgent()

    def update_state(self, red_action: str, blue_action: str):
        """
        Simulates updating the environment state based on red and blue team actions.
        """
        print(f"[Environment] Red performed: {red_action}, Blue performed: {blue_action}")
        
        # Simple state update logic
        if "brute_force_ssh" in red_action and "block_ip" in blue_action:
            self.current_state["alerts"].append("Brute force mitigated.")
        elif "exploit_vulnerability" in red_action and "patch_vulnerability" in blue_action:
            self.current_state["alerts"].append("Vulnerability patched.")
        else:
            self.current_state["alerts"].append(f"Action: {red_action} vs {blue_action}")
        
        # Simulate some state changes
        self.current_state["network_status"] = random.choice(["normal", "elevated_alert"])
        self.current_state["honeypot_health"] = random.choice(["good", "compromised"])
        
        print(f"[Environment] New state: {self.current_state}")

    def run_simulation(self, num_steps: int = 10):
        """
        Runs a simplified blue-red simulation.
        """
        print("Starting Autonomous Blue-Red Simulation...")
        for step in range(num_steps):
            print(f"\n--- Simulation Step {step + 1} ---")
            
            red_action = self.red_agent.generate_action(self.current_state)
            blue_action = self.blue_agent.generate_action(self.current_state, red_action)
            
            self.update_state(red_action, blue_action)
            time.sleep(0.5) # Simulate time passing

        print("\nAutonomous Blue-Red Simulation Finished.")

if __name__ == "__main__":
    simulator = SimulationEnvironment()
    simulator.run_simulation()
