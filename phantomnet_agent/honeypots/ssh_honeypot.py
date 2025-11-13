import socket
import paramiko
import threading
import random # Import random
from .base import Honeypot

class SSHHoneypot(Honeypot):
    # Define a list of possible SSH banners
    SSH_BANNERS = [
        "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2",
        "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3",
        "SSH-2.0-OpenSSH_5.3",
        "SSH-2.0-OpenSSH_7.9p1 Debian-10",
        "SSH-2.0-dropbear_2018.76",
        "SSH-2.0-libssh-0.9.3",
    ]

    def run(self):
        class SSHServer(paramiko.ServerInterface):
            def __init__(self, addr, port, log_event, submit_to_ledger, banner, cognitive_core):
                self.addr = addr
                self.port = port
                self.log_event = log_event
                self.submit_to_ledger = submit_to_ledger
                self.banner = banner # Store the selected banner
                self.cognitive_core = cognitive_core

            def check_auth_password(self, username, password):
                log_data = f"SSH login attempt: user={username}, password={password}"
                print(f"[!] {log_data}")
                self.log_event(self.addr[0], self.port, log_data)
                self.submit_to_ledger(self.addr[0], self.port, log_data)

                # Cognitive analysis
                if self.cognitive_core:
                    threat_data = {"request_frequency": 150, "payload": password} # Example data
                    analysis = self.cognitive_core.analyze_threat(threat_data)
                    print(f"[!] Cognitive Analysis: {analysis}")

                return paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return 'password'

            def check_channel_request(self, kind, chanid):
                log_data = f"SSH channel request: kind={kind}, chanid={chanid}"
                print(f"[!] {log_data}")
                self.log_event(self.addr[0], self.port, log_data)
                return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        sock = None # Initialize sock to None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.port))
            sock.listen(100)
            print(f"[+] SSH Honeypot active on port {self.port}")

            while not self.shutdown_event.is_set():
                try:
                    conn, addr = sock.accept()
                    print(f"[+] SSH connection from {addr[0]}:{addr[1]}")
                    transport = paramiko.Transport(conn)
                    transport.add_server_key(paramiko.RSAKey.generate(2048))
                    # Randomly select a banner for each connection
                    selected_banner = random.choice(self.SSH_BANNERS)
                    transport.set_banner(selected_banner)
                    server = SSHServer(addr, self.port, self.log_event, self.submit_to_ledger, selected_banner, self.cognitive_core)
                    transport.start_server(server=server)
                except socket.timeout:
                    continue
                except socket.error as e:
                    continue
                except Exception as e:
                    print(f"[-] Error handling SSH connection: {e}")
                    continue
        except Exception as e:
            print(f"[-] SSH Honeypot on port {self.port} failed: {e}")
        finally:
            if sock: # Check if sock was successfully created before closing
                sock.close()
            print(f"[+] SSH Honeypot on port {self.port} stopped.")
