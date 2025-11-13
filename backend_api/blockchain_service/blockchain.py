import hashlib
import json
from time import time
from urllib.parse import urlparse
import requests
from sqlalchemy.orm import Session
from backend_api.database import Block as DBBlock # Alias to avoid name collision

class Blockchain:
    def __init__(self, db: Session):
        self.db = db
        print(f"Blockchain __init__: Initializing. Current DB session: {id(self.db)}")
        self.chain = self._load_chain_from_db()
        print(f"Blockchain __init__: Chain loaded from DB: {len(self.chain)} blocks.")
        self.current_transactions = []
        self.nodes = set()

    def _load_chain_from_db(self):
        print(f"Blockchain _load_chain_from_db: Loading chain from DB for session {id(self.db)}.")
        db_blocks = self.db.query(DBBlock).order_by(DBBlock.index).all()
        print(f"Blockchain _load_chain_from_db: Raw DB blocks found: {db_blocks}")
        chain = []
        for db_block in db_blocks:
            # Reconstruct Block objects from DBBlock
            block_data = {
                'index': db_block.index,
                'timestamp': db_block.timestamp.timestamp(), # Convert datetime to timestamp
                'transactions': json.loads(db_block.data), # Assuming data stores transactions
                'proof': db_block.proof,
                'previous_hash': db_block.previous_hash,
                'hash': db_block.hash,
                'merkle_root': db_block.merkle_root
            }
            chain.append(block_data) # Store as dict for now, can convert to Block object if needed
        print(f"Blockchain _load_chain_from_db: Found {len(chain)} blocks in DB.")
        return chain

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: A blockchain
        :return: True if valid, False if not
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our Consensus Algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/blockchain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            # Clear current chain and transactions, then load new chain
            self.db.query(DBBlock).delete()
            for block_data in new_chain:
                db_block = DBBlock(
                    index=block_data['index'],
                    timestamp=datetime.datetime.fromtimestamp(block_data['timestamp']),
                    data=json.dumps(block_data['transactions']),
                    proof=block_data['proof'],
                    previous_hash=block_data['previous_hash'],
                    hash=block_data['hash'],
                    merkle_root=block_data.get('merkle_root')
                )
                self.db.add(db_block)
            self.db.commit()
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        # Save to database
        db_block = DBBlock(
            index=block['index'],
            timestamp=datetime.datetime.fromtimestamp(block['timestamp']),
            data=json.dumps(block['transactions']),
            proof=block['proof'],
            previous_hash=block['previous_hash'],
            hash=self.hash(block) # Calculate hash for DB storage
        )
        self.db.add(db_block)
        self.db.commit()
        self.db.refresh(db_block) # Refresh to get auto-generated fields like ID

        print(f"Blockchain new_block: Before append, self.chain has {len(self.chain)} blocks.")
        self.chain.append(block)
        print(f"Blockchain new_block: Added block {block['index']}. Chain now has {len(self.chain)} blocks.")
        return db_block # Return the DBBlock object

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block.index + 1

    @property
    def last_block(self):
        # Return the last block from the in-memory chain
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the Proof
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False otherwise
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
