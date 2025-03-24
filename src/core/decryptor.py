import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode
import logging

def decrypt_message(encrypted_message: str, password: str) -> str:
    try:
        # Decode the Base64-encoded data
        data = b64decode(encrypted_message)

        # Extract metadata length
        metadata_length = int.from_bytes(data[:4], byteorder="big")
        logging.debug(f"Metadata length: {metadata_length}")

        # Extract metadata
        metadata_start = 4
        metadata_end = metadata_start + metadata_length
        metadata = json.loads(data[metadata_start:metadata_end].decode())
        logging.debug(f"Metadata: {metadata}")

        # Extract lengths from metadata
        salt_length = metadata["salt_length"]
        iv_length = metadata["iv_length"]
        kdf_iterations = metadata["kdf_iterations"]

        # Extract ciphertext, IV, salt, and tag
        start = metadata_end
        end_ciphertext = len(data) - salt_length - iv_length - 16
        ciphertext = data[start:end_ciphertext]
        iv = data[end_ciphertext:end_ciphertext + iv_length]
        salt = data[end_ciphertext + iv_length:end_ciphertext + iv_length + salt_length]
        tag = data[-16:]

        # Validate extracted lengths
        logging.debug(f"Extracted lengths - IV: {len(iv)}, Salt: {len(salt)}, Tag: {len(tag)}")
        if len(iv) != iv_length:
            raise ValueError(f"Invalid IV length: expected {iv_length}, got {len(iv)}")

        # Derive the encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=kdf_iterations,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())

        # Create the cipher for decryption
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend(),
        ).decryptor()

        # Decrypt and finalize
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    except ValueError as ve:
        logging.error(f"Decryption error: {ve}")
        raise
    except Exception as e:
        logging.error("Unexpected error during decryption.")
        raise
