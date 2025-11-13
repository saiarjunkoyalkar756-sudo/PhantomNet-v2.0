import hashlib
import datetime
import json
from sqlalchemy.orm import Session
from backend_api.database import Block

class PhantomChain:
    """
    A decentralized trust fabric for PhantomNet, with SQLAlchemy persistence.
    """
    def __init__(self, db_session):
        self.db = db_session
        self.chain = self._load_chain_from_db()
        if not self.chain:
            self.chain = [self._create_and_save_genesis_block()]
        print("Initializing PhantomChain with shared SQLAlchemy session...")

    def _load_chain_from_db(self):
        chain_data = self.db.query(Block).order_by(Block.index).all()
        chain = []
        for block_db in chain_data:
            block_data = {
                'index': block_db.index,
                'timestamp': block_db.timestamp.timestamp(), # Convert datetime to timestamp
                'data': block_db.data, # Directly use the stored data
                'proof': block_db.proof,
                'previous_hash': block_db.previous_hash,
                'hash': block_db.hash,
                'merkle_root': block_db.merkle_root
            }
            chain.append(block_data) # Store as dict for now, can convert to Block object if needed
        return chain

    def _create_and_save_genesis_block(self):
        genesis_block_data = {
            'index': 1,
            'timestamp': datetime.datetime.utcnow(),
            'transactions': [],
            'proof': 100,
            'previous_hash': '1',
        }
        genesis_block_hash = hashlib.sha256(json.dumps(genesis_block_data, sort_keys=True).encode()).hexdigest()
        
        genesis_block = Block(
            index=genesis_block_data['index'],
            timestamp=genesis_block_data['timestamp'],
            data="Genesis Block",
            proof=genesis_block_data['proof'],
            previous_hash=genesis_block_data['previous_hash'],
            hash=genesis_block_hash
        )
        self.db.add(genesis_block)
        self.db.commit()
        return genesis_block

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block_data):
        latest_block = self.get_latest_block()
        
        new_block_index = latest_block['index'] + 1
        new_block_timestamp = datetime.datetime.utcnow()
        new_block_previous_hash = latest_block['hash']
        new_block_proof = 100 # Placeholder for actual proof of work
        new_block_hash = hashlib.sha256(json.dumps({
            'index': new_block_index,
            'timestamp': new_block_timestamp.timestamp(),
            'transactions': new_block_data,
            'proof': new_block_proof,
            'previous_hash': new_block_previous_hash
        }, sort_keys=True).encode()).hexdigest()

        new_block = Block(
            index=new_block_index,
            timestamp=new_block_timestamp,
            data=json.dumps(new_block_data),
            previous_hash=new_block_previous_hash,
            hash=new_block_hash,
            proof=new_block_proof
        )
        self.db.add(new_block)
        self.db.commit()
        self.chain.append(new_block.to_dict()) # Append dictionary representation to in-memory chain
        print(f"Added new block to the PhantomChain and database: {new_block.hash}")
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Recalculate hash for current_block to verify integrity
            recalculated_hash = hashlib.sha256(json.dumps({
                'index': current_block['index'],
                'timestamp': current_block['timestamp'],
                'transactions': json.loads(current_block['data']), # Assuming data is stored as JSON string
                'proof': current_block['proof'],
                'previous_hash': current_block['previous_hash']
            }, sort_keys=True).encode()).hexdigest()

            if current_block['hash'] != recalculated_hash:
                print(f"Chain is invalid: Block {current_block['index']} has been tampered with. Stored hash: {current_block['hash']}, Recalculated hash: {recalculated_hash}")
                return False

            if current_block['previous_hash'] != previous_block['hash']:
                print(f"Chain is invalid: Link between block {previous_block['index']} and {current_block['index']} is broken.")
                return False
        
        print("PhantomChain is valid.")
        return True