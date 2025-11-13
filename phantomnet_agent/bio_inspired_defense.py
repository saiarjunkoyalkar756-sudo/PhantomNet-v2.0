import random
import time

class HoneypotCell:
    def __init__(self, id: int, location: str):
        self.id = id
        self.location = location
        self.infection_level = 0.0 # 0.0 to 1.0, representing threat severity
        self.is_quarantined = False

    def detect_threat(self, severity: float):
        """Simulates a honeypot detecting a threat and updating its infection level."""
        self.infection_level = min(1.0, self.infection_level + severity)
        print(f"Honeypot {self.id} at {self.location} detected threat. Infection level: {self.infection_level:.2f}")

    def get_signal(self) -> float:
        """Returns the current infection level as a signal to the global system."""
        return self.infection_level

    def quarantine(self):
        """
        Simulates quarantining the honeypot.
        """
        self.is_quarantined = True
        print(f"Honeypot {self.id} at {self.location} has been quarantined.")

    def divert_traffic(self):
        """
        Simulates diverting traffic from the honeypot.
        """
        print(f"Traffic to Honeypot {self.id} at {self.location} has been diverted.")

class GlobalImmuneSystem:
    def __init__(self, honeypot_cells: list[HoneypotCell], threshold: float = 0.7):
        self.honeypot_cells = honeypot_cells
        self.global_threat_threshold = threshold

    def aggregate_signals(self) -> float:
        """Aggregates infection signals from all honeypot cells."""
        total_infection = sum(cell.get_signal() for cell in self.honeypot_cells)
        average_infection = total_infection / len(self.honeypot_cells) if self.honeypot_cells else 0.0
        print(f"Global Immune System: Aggregated average infection level: {average_infection:.2f}")
        return average_infection

    def trigger_response(self):
        """Triggers a global immune response based on aggregated signals."""
        average_infection = self.aggregate_signals()

        if average_infection >= self.global_threat_threshold:
            print(f"Global Immune System: Threat threshold ({self.global_threat_threshold}) exceeded! Triggering global response.")
            for cell in self.honeypot_cells:
                if cell.get_signal() > (self.global_threat_threshold * 0.8) and not cell.is_quarantined: # Cells above 80% of global threshold
                    cell.quarantine()
                    cell.divert_traffic()
            print("Global immune response actions taken.")
        else:
            print("Global Immune System: Threat level is normal. No global response triggered.")

if __name__ == "__main__":
    # Simulate a few honeypot cells
    cells = [
        HoneypotCell(id=1, location="North America"),
        HoneypotCell(id=2, location="Europe"),
        HoneypotCell(id=3, location="Asia"),
    ]

    immune_system = GlobalImmuneSystem(honeypot_cells=cells, threshold=0.6)

    print("--- Initial State ---")
    immune_system.trigger_response()

    print("\n--- Simulating Threats ---")
    cells[0].detect_threat(0.3)
    cells[1].detect_threat(0.4)
    immune_system.trigger_response()

    print("\n--- Simulating More Threats ---")
    cells[0].detect_threat(0.5)
    cells[2].detect_threat(0.7)
    immune_system.trigger_response()

    print("\n--- Simulating High Threat ---")
    cells[1].detect_threat(0.8)
    immune_system.trigger_response()
