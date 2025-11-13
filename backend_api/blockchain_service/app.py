from fastapi import FastAPI
import threading
import os
from backend_api.database import create_db_and_tables
from . import consumer

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    create_db_and_tables()
    thread = threading.Thread(target=consumer.main)
    thread.start()

@app.get("/")
def read_root():
    return {"Hello": "Blockchain Service"}
