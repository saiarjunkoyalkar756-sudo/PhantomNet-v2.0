import socket
from .base import Honeypot

class TelnetHoneypot(Honeypot):
    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        s.bind(("0.0.0.0", self.port))
        s.listen(5)
        print(f"[+] Telnet Honeypot active on port {self.port}")

        while not self.shutdown_event.is_set():
            try:
                conn, addr = s.accept()
                conn.sendall(b"Login: ")
                username = conn.recv(1024).strip().decode(errors='ignore')
                conn.sendall(b"Password: ")
                password = conn.recv(1024).strip().decode(errors='ignore')
                
                log_data = f"Telnet login attempt: user={username}, password={password}"
                print(f"[!] {log_data}")
                self.log_event(addr[0], self.port, log_data)
                self.submit_to_ledger(addr[0], self.port, log_data)
                
                conn.sendall(b"\nLogin incorrect\n")
                conn.close()
            except socket.error:
                pass

        s.close()
        print(f"[+] Telnet Honeypot on port {self.port} stopped.")
