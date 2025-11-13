import pika
import json
from fastapi import FastAPI, Request, HTTPException, Depends
import os
import datetime
from backend_api.database import get_db, AttackLog
from sqlalchemy.orm import Session

app = FastAPI()

rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")

@app.post("/logs/ingest")
async def ingest_log_entry(
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        log_data = await request.json()

        # Create a new AttackLog entry in the database
        new_log = AttackLog(
            ip=log_data.get("ip"),
            port=log_data.get("port"),
            data=log_data.get("data"),
            timestamp=datetime.datetime.now()
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log) # Refresh to get the generated ID and timestamp

        # Prepare message to publish to RabbitMQ, including the log ID
        message_to_publish = {
            "id": new_log.id,
            "ip": new_log.ip,
            "port": new_log.port,
            "data": new_log.data,
            "timestamp": new_log.timestamp.isoformat() # ISO format for datetime
        }

        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        channel = connection.channel()
        channel.queue_declare(queue='attack_logs')
        channel.basic_publish(exchange='',
                              routing_key='attack_logs',
                              body=json.dumps(message_to_publish))
        connection.close()

        return {"message": "Log entry ingested and published to RabbitMQ", "log_id": new_log.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
