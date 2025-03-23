import argparse
import logging
from src.core.encryptor import encrypt_message
from src.core.decryptor import decrypt_with_tracking

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a message.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt a message")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt a message")
    parser.add_argument("-m", "--message", type=str, required=True, help="The message to encrypt or decrypt")
    parser.add_argument("-p", "--password", type=str, required=True, help="The password for encryption or decryption")

    args = parser.parse_args()

    if args.encrypt:
        try:
            logging.info("Encrypting the message...")
            encrypted_data = encrypt_message(args.message, args.password)
            logging.info("Encryption successful. Here is your encrypted data:")
            print(encrypted_data)
        except Exception as e:
            logging.error(f"Encryption failed: {e}")

    elif args.decrypt:
        try:
            logging.info("Decrypting the message...")
            decrypted_data = decrypt_with_tracking(args.message, args.password)
            logging.info("Decryption successful. Here is your decrypted message:")
            print(decrypted_data)
        except ValueError as ve:
            logging.error(f"Decryption failed: {ve}")
        except Exception as e:
            logging.error(f"Unexpected error during decryption: {e}")


if __name__ == "__main__":
    main()
