from cryptography.fernet import Fernet
import os

KEY_FILE = "/app/secret.key"

def load_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

key = load_key()
cipher = Fernet(key)

def encrypt_data(data: str) -> bytes:
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes) -> str:
    return cipher.decrypt(encrypted_data).decode()
