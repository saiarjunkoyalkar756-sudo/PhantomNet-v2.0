import json, os, threading, importlib, sys, time
from .utils.logger import log_event
from blockchain_layer.blockchain_client import submit_to_ledger
from .cognitive_core import CognitiveCore

CONFIG = json.load(open(os.path.join(os.path.dirname(__file__), "config.json")))
HONEYPOTS = {}

def load_honeypots():
    honeypots_dir = os.path.join(os.path.dirname(__file__), "honeypots")
    for filename in os.listdir(honeypots_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = f"phantomnet_agent.honeypots.{filename[:-3]}"
            module = importlib.import_module(module_name)
            for item in dir(module):
                obj = getattr(module, item)
                if isinstance(obj, type) and issubclass(obj, object) and item != "Honeypot":
                    HONEYPOTS[f"{filename[:-3]}.{item}"] = obj

def start_honeypots():
    load_honeypots()
    ports = CONFIG["ports"]
    honeypot_mapping = CONFIG.get("honeypots", {})
    shutdown_event = threading.Event()
    threads = []

    cognitive_core = CognitiveCore()

    for port in ports:
        honeypot_class_str = honeypot_mapping.get(str(port))
        if honeypot_class_str:
            honeypot_class = HONEYPOTS.get(honeypot_class_str)
            if honeypot_class:
                honeypot = honeypot_class(port, log_event, submit_to_ledger, shutdown_event, cognitive_core)
                t = threading.Thread(target=honeypot.run)
                t.daemon = True
                t.start()
                threads.append(t)
            else:
                print(f"[-] Unknown honeypot class: {honeypot_class_str}")
        else:
            print(f"[-] No honeypot mapping for port: {port}")

    print("[*] PhantomNet Agent started...")
    print("[*] Press Ctrl+C to stop.")

    try:
        while not shutdown_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down PhantomNet Agent...")
        shutdown_event.set()
        for t in threads:
            t.join()
        print("[*] Agent stopped.")

if __name__ == "__main__":
    start_honeypots()
