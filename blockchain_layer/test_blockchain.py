import pytest
import os
import json
from blockchain_layer.blockchain import Blockchain, BLOCKCHAIN_FILE

# Ensure a clean blockchain file for each test
@pytest.fixture(autouse=True)
def clean_blockchain_file():
    if os.path.exists(BLOCKCHAIN_FILE):
        os.remove(BLOCKCHAIN_FILE)
    yield
    if os.path.exists(BLOCKCHAIN_FILE):
        os.remove(BLOCKCHAIN_FILE)

def test_new_blockchain_creates_genesis_block(db_session):
    blockchain = Blockchain(db_session)
    assert len(blockchain.chain) == 1
    assert blockchain.chain[0]['index'] == 1
    assert blockchain.chain[0]['previous_hash'] == '1'
    assert blockchain.chain[0]['proof'] == 100

def test_new_transaction_adds_to_current_transactions(db_session):
    blockchain = Blockchain(db_session)
    blockchain.new_transaction("sender1", "recipient1", 10)
    assert len(blockchain.current_transactions) == 1
    assert blockchain.current_transactions[0]['sender'] == "sender1"

def test_new_block_resets_current_transactions(db_session):
    blockchain = Blockchain(db_session)
    blockchain.new_transaction("sender1", "recipient1", 10)
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    previous_hash = blockchain.hash(last_block)
    blockchain.new_block(proof, previous_hash)
    assert len(blockchain.current_transactions) == 0

def test_hash_block_produces_consistent_hash():
    block = {
        'index': 1,
        'timestamp': 12345,
        'transactions': [],
        'proof': 100,
        'previous_hash': '1',
    }
    hash1 = Blockchain.hash(block)
    hash2 = Blockchain.hash(block)
    assert hash1 == hash2

def test_proof_of_work_finds_valid_proof(db_session):
    blockchain = Blockchain(db_session)
    last_proof = blockchain.last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    assert Blockchain.valid_proof(last_proof, proof) is True

def test_blockchain_persistence(db_session):
    blockchain1 = Blockchain(db_session)
    blockchain1.new_transaction("sender_persist", "recipient_persist", 50)
    last_block = blockchain1.last_block
    last_proof = last_block['proof']
    proof = blockchain1.proof_of_work(last_proof)
    previous_hash = blockchain1.hash(last_block)
    blockchain1.new_block(proof, previous_hash)
    blockchain1.save_chain()

    # Load a new blockchain instance and check its state
    blockchain2 = Blockchain(db_session)
    assert len(blockchain2.chain) == 2
    assert blockchain2.chain[1]['transactions'][0]['sender'] == "sender_persist"
    assert blockchain2.chain[1]['transactions'][0]['amount'] == 50
