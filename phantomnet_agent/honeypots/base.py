class Honeypot:
    def __init__(self, port, log_event, submit_to_ledger, shutdown_event, cognitive_core=None):
        self.port = port
        self.log_event = log_event
        self.submit_to_ledger = submit_to_ledger
        self.shutdown_event = shutdown_event
        self.cognitive_core = cognitive_core

    def run(self):
        raise NotImplementedError
