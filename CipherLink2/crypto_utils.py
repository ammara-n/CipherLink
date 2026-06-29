from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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





def generate_user_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes


def derive_private_key_encryption_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )

    derived_key = kdf.derive(password.encode("utf-8"))

    return base64.urlsafe_b64encode(derived_key)


def encrypt_private_key(private_key_bytes, password):
    salt = os.urandom(16)

    encryption_key = derive_private_key_encryption_key(
        password,
        salt
    )

    cipher = Fernet(encryption_key)
    encrypted_private_key = cipher.encrypt(private_key_bytes)

    return encrypted_private_key, salt


def decrypt_private_key(encrypted_private_key, password, salt):
    encryption_key = derive_private_key_encryption_key(
        password,
        salt
    )

    cipher = Fernet(encryption_key)
    private_key_bytes = cipher.decrypt(encrypted_private_key)

    return serialization.load_pem_private_key(
        private_key_bytes,
        password=None
    )


def load_public_key_from_bytes(public_key_bytes):
    return serialization.load_pem_public_key(
        public_key_bytes
    )

def encrypt_for_recipient(public_key_bytes, message):
    recipient_public_key = load_public_key_from_bytes(
        public_key_bytes
    )

    # Create a new one-time Fernet key for this message.
    message_key = Fernet.generate_key()
    message_cipher = Fernet(message_key)

    # Encrypt the actual message.
    ciphertext = message_cipher.encrypt(
        message.encode("utf-8")
    )

    # Encrypt the one-time key using the recipient's RSA public key.
    encrypted_key = recipient_public_key.encrypt(
        message_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext, encrypted_key


def decrypt_received_message(
    private_key,
    encrypted_key,
    ciphertext
):
    # Unlock the one-time Fernet key using the recipient's private key.
    message_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Use the Fernet key to decrypt the actual message.
    message_cipher = Fernet(message_key)

    return message_cipher.decrypt(
        ciphertext
    ).decode("utf-8")


def encrypt_file_for_recipient(public_key_bytes, file_bytes):
    recipient_public_key = load_public_key_from_bytes(
        public_key_bytes
    )

    file_key = Fernet.generate_key()
    file_cipher = Fernet(file_key)

    encrypted_file = file_cipher.encrypt(file_bytes)

    encrypted_key = recipient_public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_file, encrypted_key


def decrypt_received_file(
    private_key,
    encrypted_key,
    encrypted_file
):
    file_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    file_cipher = Fernet(file_key)

    return file_cipher.decrypt(encrypted_file)