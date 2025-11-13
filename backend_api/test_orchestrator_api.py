import sys
import os
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock
import time
import hashlib
import json
import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend_api.api_gateway.app import app, get_db
from backend_api.database import Base, Block, PhantomChainDB, User, SessionToken, PasswordResetToken, AttackLog, BlacklistedIP, RecoveryCode, Agent, AgentCredential, CognitiveMemoryDB

# Override the get_db dependency to use the in-memory database
def override_get_db():
    try:
        db = TestOrchestratorAPI.TestingSessionLocal()
        yield db
    finally:
        db.close()

class TestOrchestratorAPI(unittest.TestCase):
    # Class-level attribute to hold TestingSessionLocal for override_get_db
    TestingSessionLocal = None

    def setUp(self):
        # Use an in-memory SQLite database for testing
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        self.TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        Base.metadata.create_all(bind=self.engine)
        
        # Apply the dependency override
        app.dependency_overrides[get_db] = override_get_db
        
        # Create genesis block for the test database
        db = self.TestingSessionLocal()
        try:
            if db.query(Block).count() == 0:
                genesis_block_data = {
                    'index': 1,
                    'timestamp': time.time(),
                    'transactions': [],
                    'proof': 100,
                    'previous_hash': '1',
                }
                genesis_block_hash = hashlib.sha256(json.dumps(genesis_block_data, sort_keys=True).encode()).hexdigest()
                
                genesis_block = Block(
                    index=genesis_block_data['index'],
                    timestamp=datetime.datetime.fromtimestamp(genesis_block_data['timestamp']),
                    data=json.dumps(genesis_block_data['transactions']),
                    proof=genesis_block_data['proof'],
                    previous_hash=genesis_block_data['previous_hash'],
                    hash=genesis_block_hash
                )
                db.add(genesis_block)
                db.commit()
        finally:
            db.close()
        
        # Mock Redis client
        self.mock_redis_client = MagicMock()
        self.mock_redis_client.pipeline.return_value.incr.return_value = None
        self.mock_redis_client.pipeline.return_value.expire.return_value = None
        self.mock_redis_client.pipeline.return_value.execute.return_value = [1, 60] # Simulate successful incr and expire
        self.patcher_redis = patch('backend_api.api_gateway.app.redis_client', new=self.mock_redis_client)
        self.patcher_redis.start()
        
        self.client = TestClient(app)

    def tearDown(self):
        Base.metadata.drop_all(bind=self.engine)
        self.patcher_redis.stop()

    def test_handle_threat_endpoint(self):
        print("\n--- Testing /orchestrator/threats/ endpoint ---")
        response = self.client.post("/api/orchestrator/threats/", json={"threat_string": "suspicious_activity"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["message"], "Threat analyzed.")
        self.assertEqual(data["analysis"]["threat_level"], "medium")

    def test_validate_module_endpoint(self):
        print("\n--- Testing /orchestrator/marketplace/validate endpoint ---")
        module_data = {
            "developer_id": "api_test_dev",
            "module_name": "api_test_module",
            "module_code": "def test(): pass"
        }
        response = self.client.post("/api/orchestrator/marketplace/validate", json=module_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "Module submitted for validation. Check the blockchain for confirmation."})

    def test_get_blockchain_endpoint(self):
        print("\n--- Testing /orchestrator/blockchain/ endpoint ---")
        response = self.client.get("/api/orchestrator/blockchain/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("chain", data)
        self.assertIsInstance(data["chain"], list)
        self.assertEqual(len(data["chain"]), 4)
        self.assertEqual(data["chain"][0]["data"], "[]")

if __name__ == "__main__":
    unittest.main()

