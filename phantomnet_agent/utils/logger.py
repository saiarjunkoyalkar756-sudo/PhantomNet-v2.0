import datetime, os

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "logs")

def log_event(ip, port, data):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "attacks.log"), "a") as f:
        f.write(f"{datetime.datetime.now()} | IP:{ip} | Port:{port} | Data:{data}\n")
