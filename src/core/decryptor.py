import base64
import logging
import os
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature

# Configurable parameters
KDF_ITERATIONS = 200_000
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16
HMAC_LENGTH = 32
MAC_IDENTIFIER = uuid.getnode()  # Get system's MAC address as identifier

# Track decryption attempts
ATTEMPTS = {}
MAX_ATTEMPTS = 3


def track_decryption():
    """
    Tracks decryption attempts based on the system's MAC address.
    Raises an error if the maximum attempts are exceeded.
    """
    global ATTEMPTS
    if MAC_IDENTIFIER not in ATTEMPTS:
        ATTEMPTS[MAC_IDENTIFIER] = 0
    ATTEMPTS[MAC_IDENTIFIER] += 1

    if ATTEMPTS[MAC_IDENTIFIER] > MAX_ATTEMPTS:
        logging.error("Maximum decryption attempts exceeded.")
        raise ValueError("Maximum decryption attempts exceeded for this system.")
    logging.info(f"Decryption attempt {ATTEMPTS[MAC_IDENTIFIER]}/{MAX_ATTEMPTS}")


def secure_decrypt(encrypted_data: str, password: str) -> str:
    """
    Decrypts an encrypted message using AES-CBC and validates its integrity.

    Args:
        encrypted_data (str): The encrypted message in Base64 format.
        password (str): The password to derive the decryption key.

    Returns:
        str: The decrypted plaintext message.

    Raises:
        ValueError: If the encrypted data is invalid or integrity check fails.
    """
    try:
        logging.debug("Starting decryption process...")
        data = base64.b64decode(encrypted_data.encode())
        logging.debug(f"Decoded data length: {len(data)}")

        # Extract components
        ciphertext = data[:-HMAC_LENGTH - IV_LENGTH - SALT_LENGTH]
        iv = data[-HMAC_LENGTH - IV_LENGTH - SALT_LENGTH:-HMAC_LENGTH - SALT_LENGTH]
        salt = data[-HMAC_LENGTH - SALT_LENGTH:-HMAC_LENGTH]
        hmac_digest = data[-HMAC_LENGTH:]

        logging.debug(f"IV (length {len(iv)}): {iv.hex()}")
        logging.debug(f"Salt (length {len(salt)}): {salt.hex()}")
        logging.debug(f"Ciphertext (length {len(ciphertext)}): {ciphertext.hex()}")
        logging.debug(f"HMAC Digest (length {len(hmac_digest)}): {hmac_digest.hex()}")
        # Log the extracted and computed HMAC
        logging.debug(f"Extracted HMAC: {hmac_digest.hex()}")
        logging.debug(f"Computed HMAC during decryption: {hmac.finalize().hex()}")



        # Derive the encryption key
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        key = kdf.derive(password.encode())
        logging.debug("Key derivation successful.")

        # Verify HMAC for integrity
        hmac = HMAC(key, SHA256())
        hmac.update(ciphertext + iv + salt)
        hmac.verify(hmac_digest)
        logging.debug("HMAC verification successful.")

        # Decrypt the message
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        logging.debug("Cipher decryption successful.")

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        logging.debug("Padding removed successfully.")

        return message.decode()

    except InvalidSignature:
        logging.error("HMAC verification failed. Data integrity check failed.")
        raise ValueError("Data integrity check failed. Potential tampering detected.")
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise ValueError(f"Decryption failed: {e}")


def decrypt_with_tracking(encrypted_data: str, password: str) -> str:
    """
    Decrypts a message and tracks decryption attempts.

    Args:
        encrypted_data (str): The encrypted message in Base64 format.
        password (str): The password for decryption.

    Returns:
        str: The decrypted plaintext message.
    """
    track_decryption()
    return secure_decrypt(encrypted_data, password)
