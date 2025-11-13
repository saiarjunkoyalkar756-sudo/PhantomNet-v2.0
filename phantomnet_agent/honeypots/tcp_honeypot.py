import socket
from .base import Honeypot
from ..ai_analyzer import analyze_attack

class TCPHoneypot(Honeypot):
    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        s.bind(("0.0.0.0", self.port))
        s.listen(5)
        print(f"[+] TCP Honeypot active on port {self.port}")
        
        while not self.shutdown_event.is_set():
            try:
                conn, addr = s.accept()
                data = conn.recv(2048).decode(errors="ignore")
                self.log_event(addr[0], self.port, data)
                self.submit_to_ledger(addr[0], self.port, data)
                prediction = analyze_attack(data)
                print(f"[!] Attack from {addr[0]}:{self.port} | Type: {prediction}")
                conn.close()
            except socket.error:
                pass
        
        s.close()
        print(f"[+] TCP Honeypot on port {self.port} stopped.")
