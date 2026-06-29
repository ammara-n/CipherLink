from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def load_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )

aes_key = Fernet.generate_key()
cipher = Fernet(aes_key)

def encrypt_message(message):
    return cipher.encrypt(message.encode())

def decrypt_message(ciphertext):
    return cipher.decrypt(ciphertext).decode()
def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
