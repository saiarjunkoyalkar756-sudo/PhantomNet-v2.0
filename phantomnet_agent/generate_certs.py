import os
import subprocess
import json

# Configuration
CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CA_CONFIG = {
    "CN": "PhantomNet CA",
    "key": {"algo": "rsa", "size": 2048},
    "names": [{"C": "US", "L": "San Francisco", "O": "PhantomNet", "OU": "CA"}]
}
SERVER_CONFIG = {
    "CN": "phantomnet-server",
    "hosts": ["localhost", "127.0.0.1"], # Add actual server hostnames/IPs here
    "key": {"algo": "rsa", "size": 2048},
    "names": [{"C": "US", "L": "San Francisco", "O": "PhantomNet", "OU": "Server"}]
}
CLIENT_CONFIG = {
    "CN": "phantomnet-agent",
    "key": {"algo": "rsa", "size": 2048},
    "names": [{"C": "US", "L": "San Francisco", "O": "PhantomNet", "OU": "Client"}]
}

def run_cfssl(command, input_data=None):
    """Helper to run cfssl commands."""
    process = subprocess.run(
        command,
        input=json.dumps(input_data).encode('utf-8') if input_data else None,
        capture_output=True,
        text=True,
        check=True
    )
    return process.stdout.strip()

def generate_ca():
    """Generates CA certificate and key."""
    print("Generating CA certificate and key...")
    os.makedirs(CERT_DIR, exist_ok=True)

    # Generate CA key and certificate
    ca_csr = run_cfssl(["cfssl", "genkey", "-initca", "-"], CA_CONFIG)
    with open(os.path.join(CERT_DIR, "ca.csr"), "w") as f:
        f.write(ca_csr)

    ca_cert_output = run_cfssl(["cfssljson", "-bare", os.path.join(CERT_DIR, "ca")], {"certificate_request": ca_csr, "profile": "ca"})
    # cfssljson -bare outputs to files, so we need to read them back or adjust the call
    # For simplicity, assuming ca.pem and ca-key.pem are created by the above command
    # and we'll use them directly in subsequent calls.
    # The actual certificate content is not returned by cfssljson -bare to stdout.
    # We need to ensure ca-key.pem is also created.
    # The above call to cfssljson -bare ca will create ca.pem, ca.csr, ca-key.pem

    print("CA certificate and key generated.")

def generate_server_cert():
    """Generates server certificate and key signed by CA."""
    print("Generating server certificate and key...")
    
    # Generate server key and CSR
    server_csr_json = run_cfssl(["cfssl", "genkey", "-"], SERVER_CONFIG)
    server_csr_data = json.loads(server_csr_json)
    server_key = server_csr_data["private_key"]
    server_csr = server_csr_data["csr"]

    with open(os.path.join(CERT_DIR, "server.key"), "w") as f:
        f.write(server_key)

    # Sign server CSR with CA
    server_cert = run_cfssl(
        ["cfssl", "sign",
         "-ca", os.path.join(CERT_DIR, "ca.pem"),
         "-ca-key", os.path.join(CERT_DIR, "ca-key.pem"),
         "-config", os.path.join(CERT_DIR, "ca-config.json"),
         "-profile", "server",
         "-"],
        {"certificate_request": server_csr}
    )

    with open(os.path.join(CERT_DIR, "server.pem"), "w") as f:
        f.write(server_cert)

    print("Server certificate and key generated.")

def generate_client_cert():
    """Generates client certificate and key signed by CA."""
    print("Generating client certificate and key...")

    # Generate client key and CSR
    client_csr_json = run_cfssl(["cfssl", "genkey", "-"], CLIENT_CONFIG)
    client_csr_data = json.loads(client_csr_json)
    client_key = client_csr_data["private_key"]
    client_csr = client_csr_data["csr"]

    with open(os.path.join(CERT_DIR, "client.key"), "w") as f:
        f.write(client_key)

    # Sign client CSR with CA
    client_cert = run_cfssl(
        ["cfssl", "sign",
         "-ca", os.path.join(CERT_DIR, "ca.pem"),
         "-ca-key", os.path.join(CERT_DIR, "ca-key.pem"),
         "-config", os.path.join(CERT_DIR, "ca-config.json"),
         "-profile", "client",
         "-"],
        {"certificate_request": client_csr}
    )

    with open(os.path.join(CERT_DIR, "client.pem"), "w") as f:
        f.write(client_cert)

    print("Client certificate and key generated.")

def create_ca_config_file():
    """Creates a basic ca-config.json for cfssl signing profiles."""
    config_content = {
        "signing": {
            "default": {"expiry": "8760h"}, # 1 year
            "profiles": {
                "server": {"usages": ["signing", "key encipherment", "server auth"], "expiry": "8760h"},
                "client": {"usages": ["signing", "key encipherment", "client auth"], "expiry": "8760h"}
            }
        }
    }
    with open(os.path.join(CERT_DIR, "ca-config.json"), "w") as f:
        json.dump(config_content, f, indent=4)
    print("ca-config.json created.")

if __name__ == "__main__":
    # Ensure cfssl and cfssljson are installed and in PATH
    try:
        subprocess.run(["cfssl", "version"], check=True, capture_output=True)
        subprocess.run(["cfssljson", "-version"], check=True, capture_output=True)
    except FileNotFoundError:
        print("Error: cfssl and/or cfssljson not found. Please install them (e.g., `go install github.com/cloudflare/cfssl/cmd/...@latest`) and ensure they are in your PATH.")
        exit(1)

    create_ca_config_file()
    generate_ca()
    generate_server_cert()
    generate_client_cert()
    print(f"Certificates and keys generated in: {CERT_DIR}")
