import base64
import os
import logging
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature

# Configurable parameters
KDF_ITERATIONS = 200_000  # Increased iterations for stronger key derivation
KEY_LENGTH = 32           # AES-256 requires a 32-byte key
SALT_LENGTH = 16          # Salt length in bytes
IV_LENGTH = 12            # AES-GCM requires a 12-byte IV
METADATA_LENGTH = 64      # Length to store metadata
HMAC_KEY_LENGTH = 16      # Length for HMAC key

# Encrypt Message
def encrypt_message(message: str, password: str) -> str:
    """
    Encrypts a message using AES-GCM with separate keys for encryption and HMAC.

    Args:
        message (str): The plaintext message to encrypt.
        password (str): The password to derive the encryption key.

    Returns:
        str: The encrypted message encoded in Base64 format.
    """
    # Generate unique salt and IV
    salt = os.urandom(SALT_LENGTH)  # Unique for each encryption
    iv = os.urandom(IV_LENGTH)      # Unique for each encryption

    # Derive two keys: one for encryption and one for HMAC
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password.encode())
    key_enc, key_hmac = key[:KEY_LENGTH // 2], key[KEY_LENGTH // 2:]

    # Encrypt the message using AES-GCM
    cipher = Cipher(algorithms.AES(key_enc), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Generate HMAC for integrity and authentication
    hmac = HMAC(key_hmac, SHA256())
    hmac.update(ciphertext + iv + salt)
    hmac_digest = hmac.finalize()

    logging.debug(f"Computed HMAC during encryption: {hmac.finalize().hex()}")

    # Combine all components and metadata
    metadata = {
        "kdf_iterations": KDF_ITERATIONS,
        "salt_length": SALT_LENGTH,
        "iv_length": IV_LENGTH,
        "algorithm": "AES-GCM",
    }
    metadata_encoded = json.dumps(metadata).encode()

    encrypted_data = base64.b64encode(
        metadata_encoded + ciphertext + iv + salt + hmac_digest
    ).decode()
    return encrypted_data


# Decrypt Message
def decrypt_message(encrypted_data: str, password: str) -> str:
    """
    Decrypts an encrypted message and validates its integrity.

    Args:
        encrypted_data (str): The encrypted message in Base64 format.
        password (str): The password to derive the decryption key.

    Returns:
        str: The decrypted plaintext message.

    Raises:
        ValueError: If the encrypted data is invalid or integrity check fails.
    """
    try:
        # Decode Base64
        data = base64.b64decode(encrypted_data.encode())
    except Exception:
        raise ValueError("Invalid encrypted data format.")

    # Extract metadata and components
    metadata_encoded = data[:METADATA_LENGTH]
    metadata = json.loads(metadata_encoded.decode())
    ciphertext = data[METADATA_LENGTH:-IV_LENGTH - SALT_LENGTH - HMAC_KEY_LENGTH]
    iv = data[-IV_LENGTH - SALT_LENGTH - HMAC_KEY_LENGTH:-SALT_LENGTH - HMAC_KEY_LENGTH]
    salt = data[-SALT_LENGTH - HMAC_KEY_LENGTH:-HMAC_KEY_LENGTH]
    hmac_digest = data[-HMAC_KEY_LENGTH:]

    # Validate metadata
    if metadata["algorithm"] != "AES-GCM":
        raise ValueError("Unsupported encryption algorithm.")

    # Derive two keys: one for decryption and one for HMAC
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=metadata["kdf_iterations"],
    )
    key = kdf.derive(password.encode())
    key_enc, key_hmac = key[:KEY_LENGTH // 2], key[KEY_LENGTH // 2:]

    # Verify HMAC
    hmac = HMAC(key_hmac, SHA256())
    hmac.update(ciphertext + iv + salt)
    try:
        hmac.verify(hmac_digest)
    except InvalidSignature:
        raise ValueError("Data integrity check failed. Potential tampering detected.")

    # Decrypt the message using AES-GCM
    cipher = Cipher(algorithms.AES(key_enc), modes.GCM(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()
