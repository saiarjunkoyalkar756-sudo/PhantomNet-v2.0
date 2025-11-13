import sys
import os
import unittest
import shutil
import sqlite3
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from phantomnet_agent.orchestrator import Orchestrator

class TestOrchestratorIntegration(unittest.TestCase):

    def setUp(self):
        """
        Set up a temporary in-memory SQLite database and file system for each test.
        """
        self.test_dir = "test_orchestrator"
        os.makedirs(self.test_dir, exist_ok=True)
        self.target_file = os.path.join(self.test_dir, "critical_system_file.txt")
        self.original_content = "This is the original, uncompromised state of a critical file."
        with open(self.target_file, "w") as f:
            f.write(self.original_content)

        # Set up the in-memory database for a single test
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE cognitive_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_data TEXT UNIQUE NOT NULL,
                episode_data TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE phantom_chain (
                block_index INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
        """)
        
        # Initialize the orchestrator with the in-memory DB connection
        self.orchestrator = Orchestrator(
            target_system_file=self.target_file,
            db_connection=self.conn
        )
        self.orchestrator.chrono_defense.create_snapshot(self.target_file)

    def tearDown(self):
        """
        Clean up the file system and close the database connection after each test.
        """
        shutil.rmtree(self.test_dir)
        shutil.rmtree(self.orchestrator.chrono_defense.snapshot_dir)
        self.conn.close()

    def test_critical_threat_triggers_rollback(self):
        print("\n--- Running Test Scenario: Orchestrator - Critical Threat Rollback ---")
        compromised_content = "Compromised content after attack."
        with open(self.target_file, "w") as f:
            f.write(compromised_content)
        
        critical_threat = "unauthorized_access_D"
        self.orchestrator.handle_threat(critical_threat)
        
        with open(self.target_file, "r") as f:
            self.assertEqual(f.read(), self.original_content)
        print("\n--- Verification successful: Orchestrator triggered rollback successfully. ---")

    def test_marketplace_validation_is_recorded_on_chain(self):
        print("\n--- Running Test Scenario: Orchestrator - Marketplace & Chain Integration ---")
        developer_id = "test_dev"
        module_name = "test_module"
        module_code = "def test(): pass"
        
        initial_chain_length = len(self.orchestrator.phantom_chain.chain)
        self.orchestrator.validate_marketplace_module(developer_id, module_name, module_code)
        
        db_chain = self.orchestrator.phantom_chain._load_chain_from_db()
        self.assertEqual(len(db_chain), initial_chain_length + 1)
        
        latest_block = db_chain[-1]
        self.assertEqual(latest_block.data["type"], "module_validation")
        self.assertEqual(latest_block.data["module_id"], f"{developer_id}_{module_name}")
        print("\n--- Verification successful: Marketplace validation recorded on the chain. ---")

    def test_telemetry_threat_detection_and_memory(self):
        print("\n--- Running Test Scenario: Orchestrator - Telemetry Threat Detection & Memory ---")
        high_cpu_telemetry = {"node_id": "test_node_123", "cpu_usage": 95.5}
        
        # First analysis should detect high CPU usage
        analysis1 = self.orchestrator.cognitive_core.analyze_threat(high_cpu_telemetry)
        self.assertEqual(analysis1["threat_level"], "high")
        
        # Verify it was stored in memory
        recalled_episode = self.orchestrator.cognitive_core.memory.recall_episode(str(high_cpu_telemetry))
        self.assertIsNotNone(recalled_episode)
        self.assertEqual(recalled_episode["analysis"]["threat_level"], "high")
        
        print("\n--- Verification successful: High CPU usage threat detected and stored in memory. ---")

if __name__ == "__main__":
    unittest.main()
