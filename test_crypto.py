import logging
from src.core.encryptor import encrypt_message
from src.core.decryptor import decrypt_with_tracking

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def test_encryption_decryption():
    """
    Test encryption and decryption functionality with detailed debugging.
    """
    try:
        logging.info("Starting encryption and decryption test...")
        
        # Test data
        test_password = "TestPassword"
        test_message = "This is a test message."

        # Encrypt the test message
        logging.info("Encrypting the message...")
        encrypted_message = encrypt_message(test_message, test_password)
        logging.info(f"Encrypted message: {encrypted_message}")

        # Decrypt the encrypted message
        logging.info("Decrypting the message...")
        decrypted_message = decrypt_with_tracking(encrypted_message, test_password)
        logging.info(f"Decrypted message: {decrypted_message}")

        # Verify results
        assert decrypted_message == test_message, "Decrypted message does not match the original message!"
        logging.info("Test passed: Encryption and decryption are working as expected.")

    except Exception as e:
        logging.error(f"Test failed: {e}")
        raise  # Re-raise to see full traceback if needed

# Run the test
if __name__ == "__main__":
    test_encryption_decryption()
