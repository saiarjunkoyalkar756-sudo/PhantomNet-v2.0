import pika
import json
import os
import threading
import time

from blockchain_layer.blockchain import Blockchain
from backend_api.database import get_db, Block, AttackLog # Import AttackLog model

rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")

def main():
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
    channel = connection.channel()

    channel.queue_declare(queue='attack_logs')

    def callback(ch, method, properties, body):
        message_data = json.loads(body.decode())
        log_id = message_data.get("id")

        print(f" [Blockchain Service] Received log entry with ID: {log_id}")

        db = next(get_db()) # Get a database session
        blockchain = Blockchain(db)

        try:
            # Fetch the AttackLog entry from the database
            attack_log_entry = db.query(AttackLog).filter(AttackLog.id == log_id).first()

            if attack_log_entry:
                # Add a new transaction to the blockchain using data from AttackLog
                blockchain.new_transaction(
                    sender="honeypot", # The agent is the sender
                    recipient=attack_log_entry.ip,
                    amount=1, # Placeholder, consider adding more meaningful data
                    data=attack_log_entry.data, # Include the full data
                    attack_type=attack_log_entry.attack_type, # Include predicted attack type
                    confidence_score=attack_log_entry.confidence_score # Include confidence score
                )

                # Mine a new block to record the transaction
                last_block_obj = blockchain.last_block
                last_proof = last_block_obj.proof if last_block_obj else 0
                proof = blockchain.proof_of_work(last_proof)
                previous_hash = blockchain.hash(last_block_obj.to_dict()) if last_block_obj else '1'

                new_block_obj = blockchain.new_block(proof, previous_hash)
                db.add(new_block_obj)
                db.commit()
                db.refresh(new_block_obj)
                print(f" [Blockchain Service] New block mined: {new_block_obj.index}")
            else:
                print(f" [Blockchain Service] AttackLog with ID {log_id} not found. Cannot add to blockchain.")

        except Exception as e:
            db.rollback()
            print(f" [Blockchain Service] Error processing log entry for blockchain: {e}")
        finally:
            db.close()

    channel.basic_consume(queue='attack_logs', on_message_callback=callback, auto_ack=True)

    print(' [Blockchain Service] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()

if __name__ == '__main__':
    main()
