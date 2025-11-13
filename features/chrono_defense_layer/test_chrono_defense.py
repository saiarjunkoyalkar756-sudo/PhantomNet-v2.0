import sys
import os
import unittest
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.chrono_defense_layer.chrono_defense import ChronoDefense

class TestChronoDefense(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_chrono_defense"
        os.makedirs(self.test_dir, exist_ok=True)
        self.target_file = os.path.join(self.test_dir, "system_state.txt")
        self.original_content = "This is the original, uncompromised system state."
        with open(self.target_file, "w") as f:
            f.write(self.original_content)
        
        self.snapshot_dir = os.path.join(self.test_dir, "snapshots")
        self.chrono_defense = ChronoDefense(snapshot_dir=self.snapshot_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_snapshot_and_rollback(self):
        """
        Tests the full snapshot and rollback cycle.
        """
        print("\n--- Running Test Scenario: ChronoDefense Layer ---")
        
        # 1. Create a snapshot
        snapshot_path = self.chrono_defense.create_snapshot(self.target_file)
        self.assertIsNotNone(snapshot_path)
        self.assertTrue(os.path.exists(snapshot_path))
        
        # 2. "Compromise" the original file
        compromised_content = "This is the compromised state after a simulated attack."
        with open(self.target_file, "w") as f:
            f.write(compromised_content)
        
        with open(self.target_file, "r") as f:
            self.assertEqual(f.read(), compromised_content)
            
        # 3. Find the latest snapshot
        latest_snapshot = self.chrono_defense.get_latest_snapshot(self.target_file)
        self.assertEqual(snapshot_path, latest_snapshot)
        
        # 4. Roll back to the snapshot
        rollback_successful = self.chrono_defense.rollback_to_snapshot(self.target_file, latest_snapshot)
        self.assertTrue(rollback_successful)
        
        # 5. Verify the file content is restored
        with open(self.target_file, "r") as f:
            self.assertEqual(f.read(), self.original_content)
            
        print("\n--- Verification successful: System state rolled back successfully. ---")

if __name__ == "__main__":
    unittest.main()
