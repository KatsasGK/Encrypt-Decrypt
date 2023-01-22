import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argparse
import loguru

logger = loguru.logger


def generate_key(password: str):
    password = password.encode()
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    return open("key.key", "rb").read()

def encrypt_message(message: str):
    key = load_key()
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message: bytes):
    key = load_key()
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()


def machine(message: str, action: str):
    if action == "encrypt":
        new_message = encrypt_message(message)
        logger.info("Encrypted message: " + base64.urlsafe_b64encode(new_message).decode())
    elif action == "decrypt":
        new_message = decrypt_message(base64.urlsafe_b64decode(message))
        logger.info("Decrypted message: " + new_message)
    else:
        logger.error("Enter a correct option!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt and decrypt messages using AES and PBKDF2")
    parser.add_argument("-p", "--password", type=str, help="Password to encrypt and decrypt the message")
    parser.add_argument("-m", "--message", type=str, help="The message to encrypt or decrypt")
    parser.add_argument("-a", "--action", type=str, help="The action to perform, either 'encrypt' or 'decrypt'")
    args = parser.parse_args()
    if args.password:
        generate_key(args.password)
    machine(args.message, args.action)
