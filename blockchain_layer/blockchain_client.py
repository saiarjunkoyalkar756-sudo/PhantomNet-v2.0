import json
import httpx
import os

# The collector service is running on port 8001
COLLECTOR_API_URL = "http://localhost:8001"

async def submit_to_ledger(ip, port, data):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{COLLECTOR_API_URL}/logs/ingest",
                json={
                    "ip": ip,
                    "port": port,
                    "data": data
                }
            )
            response.raise_for_status() # Raise an exception for 4xx or 5xx status codes
            print(f"[Agent] Log submitted to collector: {response.json()}")
    except httpx.RequestError as exc:
        print(f"[Agent] An error occurred while requesting {exc.request.url!r}: {exc}")
    except httpx.HTTPStatusError as exc:
        print(f"[Agent] Error response {exc.response.status_code} while requesting {exc.request.url!r}: {exc.response.text}")
