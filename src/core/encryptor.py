import base64
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

# Configurable parameters
KDF_ITERATIONS = 200_000
KEY_LENGTH = 32
SALT_LENGTH = 16
IV_LENGTH = 12

def encrypt_message(message: str, password: str) -> str:
    # Generate unique salt and IV
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)

    # Derive the encryption key
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password.encode())

    # Encrypt the message using AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Extract the authentication tag
    auth_tag = encryptor.tag

    # Combine all components and metadata
    metadata = json.dumps({
        "kdf_iterations": KDF_ITERATIONS,
        "salt_length": SALT_LENGTH,
        "iv_length": IV_LENGTH,
        "algorithm": "AES-GCM",
    }).encode()
    metadata_length = len(metadata).to_bytes(4, byteorder='big')

    encrypted_data = base64.b64encode(
        metadata_length + metadata + ciphertext + iv + salt + auth_tag
    ).decode()
    return encrypted_data
