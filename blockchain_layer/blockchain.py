import os
import json
import hashlib
import datetime # Import datetime
from time import time
from sqlalchemy.orm import Session
from backend_api.database import Block # Import the Block model

BLOCKCHAIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blockchain.json")



class Blockchain:
    """Manages the blockchain, including creating blocks, adding transactions, and handling persistence."""

    def __init__(self, db: Session):
        """Initializes a new Blockchain instance, ensuring a genesis block exists in the database."""
        self.db = db
        self.current_transactions = []
        # Ensure genesis block exists
        if not self.db.query(Block).filter(Block.index == 1).first():
            self.new_block(proof=100, previous_hash='1') # Create genesis block
            self.db.commit() # Commit the genesis block



    def new_block(self, proof: int, previous_hash: str = None) -> Block: # Returns a Block object
        """Creates a new Block and adds it to the database.

        Args:
            proof (int): The proof given by the Proof of Work algorithm.
            previous_hash (str, optional): Hash of previous Block. Defaults to None.

        Returns:
            Block: The new Block object.
        """
        last_block_obj = self.last_block # Get the last block from the database

        # Calculate Merkle root of current transactions
        transaction_hashes = [self.hash(t) for t in self.current_transactions]
        merkle_root_hash = self.merkle_root(transaction_hashes) if transaction_hashes else None

        block_data = {
            'index': (last_block_obj.index + 1) if last_block_obj else 1,
            'timestamp': datetime.datetime.fromtimestamp(time()), # Convert float timestamp to datetime object
            'transactions': self.current_transactions,
            'merkle_root': merkle_root_hash, # Add Merkle root to the block
            'proof': proof,
            'previous_hash': previous_hash or (self.hash(last_block_obj.to_dict()) if last_block_obj else '1'),
                                # Pass dictionary of last block to hash function
        }
        
        # Create a new Block object and add it to the session
        new_db_block = Block(**block_data)
        self.db.add(new_db_block)
        # self.db.commit() # Commit handled by the caller (app.py)
        # Reset the current list of transactions
        self.current_transactions = []
        return new_db_block

    def new_transaction(self, sender: str, recipient: str, amount: float, data: str = None, attack_type: str = None, confidence_score: float = None) -> int:
        """Creates a new transaction to go into the next mined Block.

        Args:
            sender (str): The address of the Sender.
            recipient (str): The address of the Recipient.
            amount (float): The amount.
            data (str): The raw attack data.
            attack_type (str): The predicted attack type.
            confidence_score (float): The confidence score of the prediction.

        Returns:
            int: The index of the Block that will hold this transaction.
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'data': data,
            'attack_type': attack_type,
            'confidence_score': confidence_score,
        })
        last_block_obj = self.last_block
        return (last_block_obj.index + 1) if last_block_obj else 1

    @staticmethod
    def hash(block: dict) -> str:
        """Creates a SHA-256 hash of a Block.

        Args:
            block (dict): A Block.

        Returns:
            str: The SHA-256 hash of the Block.
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self) -> Block | None: # Returns a Block object or None
        """Returns the last Block in the database."""
        return self.db.query(Block).order_by(Block.index.desc()).first()

    def proof_of_work(self, last_proof: int) -> int:
        """Simple Proof of Work Algorithm:
        - Find a number p' such that hash(pp') contains 4 leading zeroes
        - Where p is the previous proof, and p' is the new proof

        Args:
            last_proof (int): The previous proof.

        Returns:
            int: The new proof.
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof: int, proof: int) -> bool:
        """Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?

        Args:
            last_proof (int): Previous Proof.
            proof (int): Current Proof.

        Returns:
            bool: True if correct, False otherwise.
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    @staticmethod
    def merkle_root(hashes):
        layer = [h if isinstance(h, bytes) else hashlib.sha256(h.encode()).digest() for h in hashes]
        while len(layer) > 1:
            if len(layer) % 2:
                layer.append(layer[-1])
            layer = [hashlib.sha256(layer[i] + layer[i+1]).digest() for i in range(0, len(layer), 2)]
        return layer[0].hex()

    def is_chain_valid(self) -> bool:
        """Determines if the entire blockchain is valid by checking hashes and proofs."""
        blocks = self.db.query(Block).order_by(Block.index).all()
        if not blocks: # An empty chain is technically valid, or handle as an error
            return True

        for i in range(1, len(blocks)):
            block = blocks[i]
            last_block = blocks[i-1]

            # Check that the hash of the previous block is correct
            if block.previous_hash != self.hash(last_block.to_dict()):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block.proof, block.proof):
                return False
        return True
