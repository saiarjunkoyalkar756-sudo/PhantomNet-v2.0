from fastapi import FastAPI
import threading
import os
from . import consumer

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    thread = threading.Thread(target=consumer.main)
    thread.start()

@app.get("/")
def read_root():
    return {"Hello": "Analyzer"}