import socket
import threading
import json

class P2PNode:
    def __init__(self, host, port, cognitive_core):
        self.host = host
        self.port = port
        self.peers = set()
        self.cognitive_core = cognitive_core
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

    def start(self):
        threading.Thread(target=self.listen, daemon=True).start()
        threading.Thread(target=self.discover_peers, daemon=True).start()

    def listen(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                message = json.loads(data.decode())
                if message.get('type') == 'discovery':
                    self.peers.add(addr)
                elif message.get('type') == 'alert':
                    self.cognitive_core.handle_peer_alert(message['data'])
            except Exception as e:
                print(f"[P2P] Error while listening: {e}")

    def discover_peers(self):
        while True:
            for i in range(1, 255):
                peer_ip = f"192.168.1.{i}" # Assuming a /24 subnet for simplicity
                if peer_ip != self.host:
                    self.send_message({'type': 'discovery'}, (peer_ip, self.port))
            threading.Event().wait(60) # Discover every 60 seconds

    def broadcast(self, message):
        for peer in self.peers:
            self.send_message(message, peer)

    def send_message(self, message, peer):
        try:
            self.sock.sendto(json.dumps(message).encode(), peer)
        except Exception as e:
            print(f"[P2P] Error sending message to {peer}: {e}")
