import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from features.phantom_chain.decentralized_trust_fabric import PhantomChain

class TestPhantomChain(unittest.TestCase):

    def setUp(self):
        self.phantom_chain = PhantomChain()

    def test_chain_creation_and_validity(self):
        """
        Tests the creation of the chain and its initial validity.
        """
        print("\n--- Running Test Scenario: PhantomChain Creation and Validity ---")
        self.assertEqual(len(self.phantom_chain.chain), 1)
        self.assertTrue(self.phantom_chain.is_chain_valid())

    def test_add_block_and_maintain_validity(self):
        """
        Tests adding new blocks and ensuring the chain remains valid.
        """
        print("\n--- Running Test Scenario: Adding Blocks ---")
        self.phantom_chain.add_block({"transaction": "module_A_validated", "reward": 10})
        self.phantom_chain.add_block({"transaction": "module_B_validated", "reward": 10})
        
        self.assertEqual(len(self.phantom_chain.chain), 3)
        self.assertTrue(self.phantom_chain.is_chain_valid())

    def test_chain_tampering_detection(self):
        """
        Tests the chain's ability to detect tampering.
        """
        print("\n--- Running Test Scenario: Tampering Detection ---")
        self.phantom_chain.add_block({"transaction": "module_C_validated", "reward": 10})
        
        # Tamper with the data of a block
        print("\n--- Simulating tampering with the blockchain... ---")
        self.phantom_chain.chain[1].data = {"transaction": "module_C_validated", "reward": 1000} # Maliciously change reward
        
        self.assertFalse(self.phantom_chain.is_chain_valid())
        print("\n--- Verification successful: Chain tampering detected. ---")

if __name__ == "__main__":
    unittest.main()
