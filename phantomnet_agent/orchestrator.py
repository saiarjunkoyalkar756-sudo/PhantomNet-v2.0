import sys
import os

# Add the parent directory to the Python path to allow for package-like imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend_api.database import SessionLocal, initialize_database
from features.cognitive_core_intelligence.cognitive_core import CognitiveCore
from features.chrono_defense_layer.chrono_defense import ChronoDefense
from features.ai_threat_marketplace.phantom_exchange import PhantomExchange
from features.phantom_chain.decentralized_trust_fabric import PhantomChain
from features.synthetic_cognitive_memory.cognitive_memory import CognitiveMemory

class Orchestrator:
    """
    The central orchestrator for the PhantomNet agent.
    Initializes and integrates the various features using a shared DB session.
    """
    def __init__(self, target_system_file, db_session=None):
        self.target_system_file = target_system_file
        
        # Use provided DB session or create a new one
        self.db_session = db_session if db_session else SessionLocal()
        
        # Initialize features with the shared DB session
        self.phantom_chain = PhantomChain(db_session=self.db_session)
        self.cognitive_memory = CognitiveMemory(db_session=self.db_session)
        self.cognitive_core = CognitiveCore(cognitive_memory=self.cognitive_memory)
        self.phantom_exchange = PhantomExchange(phantom_chain=self.phantom_chain)
        self.chrono_defense = ChronoDefense()
        
        print("PhantomNet Orchestrator Initialized with shared SQLAlchemy session.")


    def handle_threat(self, threat_data: str):
        """
        Handles a new threat by analyzing it and taking appropriate action.
        """
        print(f"\n--- Orchestrator handling new threat: {threat_data} ---")
        
        analysis = self.cognitive_core.analyze_threat(threat_data)
        print(f"Cognitive Core analysis: {analysis}")
        
        if analysis.get("threat_level") == "critical":
            print("Critical threat detected. Triggering ChronoDefense rollback.")
            
            latest_snapshot = self.chrono_defense.get_latest_snapshot(self.target_system_file)
            
            if latest_snapshot:
                self.chrono_defense.rollback_to_snapshot(self.target_system_file, latest_snapshot)
            else:
                print("No snapshot available to roll back to.")
        else:
            print("Threat is not critical. No rollback required.")

    def receive_telemetry(self, telemetry_data: dict):
        """
        Receives telemetry data from an EdgeBrain and passes it to the CognitiveCore.
        """
        print(f"\n--- Orchestrator received telemetry from {telemetry_data.get('node_id')} ---")
        self.cognitive_core.analyze_threat(telemetry_data)

    def validate_marketplace_module(self, developer_id: str, module_name: str, module_code: str):
        """
        Validates a new module on the PhantomExchange.
        """
        print(f"\n--- Orchestrator validating new marketplace module: {module_name} ---")
        self.phantom_exchange.register_developer(developer_id)
        self.phantom_exchange.submit_module(developer_id, module_name, module_code)
        self.phantom_exchange.validate_module(f"{developer_id}_{module_name}")

