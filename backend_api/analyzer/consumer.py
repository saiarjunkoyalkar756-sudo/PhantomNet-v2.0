import pika
import json
import os
import threading
import time
import pandas as pd
import httpx
from datetime import datetime, timedelta

from backend_api.database import get_db, AttackLog
from backend_api.message_bus import publish_message
from .model import load_classifier_model, load_anomaly_model, extract_features

rabbitmq_host = os.getenv("RABBITMQ_HOST", "localhost")
API_GATEWAY_URL = "http://api_gateway:8000" # Assuming api_gateway is accessible via this hostname
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Load the ML models once when the consumer starts
classifier_model = load_classifier_model()
anomaly_model = load_anomaly_model()

def check_abuseipdb_sync(ip_address: str, log_id: int):
    is_verified_threat = False
    if not ABUSEIPDB_API_KEY:
        print(" [Analyzer] ABUSEIPDB_API_KEY not set. Skipping AbuseIPDB check.")
        return

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    try:
        response = httpx.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data['data']['abuseConfidenceScore'] > 50: # Threshold for considering it a verified threat
            print(f" [Analyzer] IP {ip_address} is a verified threat (AbuseIPDB score: {data['data']['abuseConfidenceScore']})")
            is_verified_threat = True

        db = next(get_db())
        try:
            attack_log_entry = db.query(AttackLog).filter(AttackLog.id == log_id).first()
            if attack_log_entry:
                attack_log_entry.is_verified_threat = is_verified_threat
                db.commit()
                db.refresh(attack_log_entry)
                print(f" [Analyzer] Updated AttackLog ID {log_id} with AbuseIPDB verification status.")
                if is_verified_threat:
                    # Trigger admin alert for verified threat
                    httpx.post(f"{API_GATEWAY_URL}/alerts/threat_verified", json={
                        "log_id": log_id,
                        "ip": ip_address,
                        "message": f"Verified threat detected from IP: {ip_address}"
                    })
        except Exception as e:
            db.rollback()
            print(f" [Analyzer] Error updating AbuseIPDB status for log {log_id}: {e}")
        finally:
            db.close()

    except httpx.RequestError as e:
        print(f" [Analyzer] Error checking AbuseIPDB for {ip_address}: {e}")
    except Exception as e:
        print(f" [Analyzer] Unexpected error during AbuseIPDB check for {ip_address}: {e}")

def get_geolocation(ip_address: str):
    try:
        response = httpx.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            return data.get('lat'), data.get('lon')
    except httpx.RequestError as e:
        print(f" [Analyzer] Error getting geolocation for {ip_address}: {e}")
    except Exception as e:
        print(f" [Analyzer] Unexpected error during geolocation for {ip_address}: {e}")
    return None, None

def main():
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
    channel = connection.channel()

    channel.queue_declare(queue='attack_logs')

    def callback(ch, method, properties, body):
        message_data = json.loads(body.decode())
        log_id = message_data.get("id")
        original_log_data = {
            "ip": message_data.get("ip"),
            "port": message_data.get("port"),
            "data": message_data.get("data"),
            "timestamp": message_data.get("timestamp")
        }

        print(f" [Analyzer] Received log entry with ID: {log_id}")

        # Get geolocation
        lat, lon = get_geolocation(original_log_data["ip"])

        # Extract features
        features_df = extract_features(original_log_data)

        # Make classification prediction
        prediction = classifier_model.predict(features_df)[0]
        prediction_proba = classifier_model.predict_proba(features_df)[0]
        confidence_score = max(prediction_proba)

        print(f" [Analyzer] Predicted attack type: {prediction} with confidence: {confidence_score:.2f}")

        # Perform anomaly detection
        anomaly_score = anomaly_model.decision_function(features_df)[0]
        is_anomaly = anomaly_model.predict(features_df)[0] == -1 # -1 for anomaly, 1 for normal

        if is_anomaly:
            print(f" [Analyzer] ANOMALY DETECTED! Anomaly score: {anomaly_score:.2f}")
            # Send anomaly alert to API Gateway
            try:
                httpx.post(f"{API_GATEWAY_URL}/alerts/anomaly", json={
                    "log_id": log_id,
                    "ip": original_log_data["ip"],
                    "port": original_log_data["port"],
                    "data": original_log_data["data"],
                    "timestamp": original_log_data["timestamp"],
                    "anomaly_score": anomaly_score,
                    "attack_type": prediction, # Include predicted attack type
                    "confidence_score": confidence_score # Include confidence score
                })
            except httpx.RequestError as e:
                print(f" [Analyzer] Failed to send anomaly alert to API Gateway: {e}")

        db = next(get_db())
        try:
            # Fetch the existing AttackLog entry and update it
            attack_log_entry = db.query(AttackLog).filter(AttackLog.id == log_id).first()
            if attack_log_entry:
                attack_log_entry.attack_type = prediction
                attack_log_entry.confidence_score = float(f"{confidence_score:.2f}")
                attack_log_entry.is_anomaly = is_anomaly
                attack_log_entry.anomaly_score = anomaly_score
                attack_log_entry.lat = lat
                attack_log_entry.lon = lon
                db.commit()
                db.refresh(attack_log_entry)
                print(f" [Analyzer] Updated AttackLog ID {log_id} with prediction, anomaly status, and geolocation.")

                # Publish to agent-events for real-time map
                publish_message("agent-events", {
                    "id": log_id,
                    "ip": original_log_data["ip"],
                    "lat": lat,
                    "lon": lon,
                    "attack_type": prediction,
                    "confidence_score": float(f"{confidence_score:.2f}"),
                    "is_anomaly": is_anomaly,
                    "anomaly_score": anomaly_score,
                    "timestamp": original_log_data["timestamp"]
                })

            else:
                print(f" [Analyzer] AttackLog with ID {log_id} not found.")

        except Exception as e:
            db.rollback()
            print(f" [Analyzer] Error updating analyzed log: {e}")
        finally:
            db.close()

        # Run AbuseIPDB check in a separate thread to avoid blocking the consumer
        if original_log_data["ip"]:
            thread = threading.Thread(target=check_abuseipdb_sync, args=(original_log_data["ip"], log_id))
            thread.start()

        # Check for repeated attacks for blacklisting (mocked)
        db_for_blacklist = next(get_db())
        try:
            five_minutes_ago = datetime.now() - timedelta(minutes=5)
            recent_attacks = db_for_blacklist.query(AttackLog).filter(
                AttackLog.ip == original_log_data["ip"],
                AttackLog.timestamp >= five_minutes_ago
            ).count()

            if recent_attacks >= 3:
                print(f" [Analyzer] Repeated attacks from {original_log_data["ip"]}. Mock blacklisting.")
                # Update all recent attacks from this IP as blacklisted
                db_for_blacklist.query(AttackLog).filter(AttackLog.ip == original_log_data["ip"], AttackLog.timestamp >= five_minutes_ago).update({"is_blacklisted": True})
                db_for_blacklist.commit()
                # Send alert to API Gateway for blacklisting
                httpx.post(f"{API_GATEWAY_URL}/alerts/blacklisted", json={
                    "ip": original_log_data["ip"],
                    "message": f"IP {original_log_data["ip"]} has been blacklisted due to repeated attacks."
                })
        except Exception as e:
            db_for_blacklist.rollback()
            print(f" [Analyzer] Error during blacklisting check: {e}")
        finally:
            db_for_blacklist.close()

    channel.basic_consume(queue='attack_logs', on_message_callback=callback, auto_ack=True)

    print(' [Analyzer] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()

if __name__ == '__main__':
    main()