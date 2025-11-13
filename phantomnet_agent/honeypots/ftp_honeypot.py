from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import ThreadedFTPServer
from .base import Honeypot
import threading

class FTPHoneypot(Honeypot):
    def run(self):
        class MyFTPHandler(FTPHandler):
            def ftp_USER(self, username):
                log_data = f"FTP user: {username}"
                print(f"[!] {log_data}")
                self.server.log_event(self.remote_ip, self.server.port, log_data)
                self.server.submit_to_ledger(self.remote_ip, self.server.port, log_data)
                self.respond("331 Password required.")

            def ftp_PASS(self, password):
                log_data = f"FTP password: {password}"
                print(f"[!] {log_data}")
                self.server.log_event(self.remote_ip, self.server.port, log_data)
                self.server.submit_to_ledger(self.remote_ip, self.server.port, log_data)
                self.respond("530 Login incorrect.")
                self.close()

        handler = MyFTPHandler
        handler.banner = "FTP Server ready."

        server = ThreadedFTPServer(("0.0.0.0", self.port), handler)
        server.log_event = self.log_event
        server.submit_to_ledger = self.submit_to_ledger
        server.port = self.port

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        print(f"[+] FTP Honeypot active on port {self.port}")

        while not self.shutdown_event.is_set():
            pass

        server.close_all()
        print(f"[+] FTP Honeypot on port {self.port} stopped.")
