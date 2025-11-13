import redis
import json
from loguru import logger
from typing import Optional

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def publish_message(channel: str, message: dict, cluster_id: Optional[str] = None, jwt_token: Optional[str] = None):
    try:
        namespaced_channel = f"{cluster_id}:{channel}" if cluster_id else channel
        full_message = {"data": message}
        if jwt_token:
            full_message["jwt"] = jwt_token
        redis_client.publish(namespaced_channel, json.dumps(full_message))
        # TODO: For backpressure with Redis Streams, use redis_client.xadd with a MAXLEN argument.
        # This current implementation uses Pub/Sub, which does not have built-in backpressure like Streams.
        logger.info(f"Published message to channel '{namespaced_channel}': {full_message}")
    except Exception as e:
        logger.error(f"Error publishing message to channel '{namespaced_channel}': {e}")

def subscribe_to_channel(channel: str, cluster_id: Optional[str] = None):
    pubsub = redis_client.pubsub()
    namespaced_channel = f"{cluster_id}:{channel}" if cluster_id else channel
    pubsub.subscribe(namespaced_channel)
    logger.info(f"Subscribed to channel '{namespaced_channel}'")
    return pubsub
