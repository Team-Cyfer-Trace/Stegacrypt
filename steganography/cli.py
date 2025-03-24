import argparse
import logging
import traceback
from Custom_crypto import encrypt_message, decrypt_message
from Image_steganography import embed_data_in_image, extract_data_from_image

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main():
    parser = argparse.ArgumentParser(
        description="Image Steganography with Encryption and Decryption"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-s", "--store", action="store_true", help="Hide and encrypt a message into an image"
    )
    group.add_argument(
        "-r", "--read", action="store_true", help="Read and decrypt a message from an image"
    )
    group.add_argument(
        "-e", "--encrypt", action="store_true", help="Encrypt a message"
    )
    group.add_argument(
        "-d", "--decrypt", action="store_true", help="Decrypt a message"
    )

    parser.add_argument("-m", "--message", type=str, help="The message to hide or encrypt")
    parser.add_argument("-p", "--password", type=str, required=True, help="The password for encryption or decryption")
    parser.add_argument("-i", "--image", type=str, help="The input image file (required for -s and -r)")
    parser.add_argument("-o", "--output", type=str, help="The output file (image for -s, text for others)")

    args = parser.parse_args()

    try:
        if args.store:
            if not args.message:
                logging.error("Message is required for hiding data (-s).")
                return
            if not args.image:
                logging.error("Image path is required for hiding data (-s).")
                return

            logging.info("Encrypting the message...")
            encrypted_message = encrypt_message(args.message, args.password)

            logging.info("Hiding encrypted data in the image...")
            embed_data_in_image(args.image, encrypted_message, args.output)

            logging.info(f"Data hidden successfully. Stego image saved to {args.output}")

        elif args.read:
            if not args.image:
                logging.error("Image path is required for reading data (-r).")
                return

            logging.info("Extracting data from the image...")
            extracted_data = extract_data_from_image(args.image)
            if not extracted_data:
                logging.error("No valid data could be extracted from the image.")
                return

            logging.info("Decrypting the extracted data...")
            decrypted_message = decrypt_message(extracted_data, args.password)

            logging.info("Decryption successful. Here is your message:")
            print(decrypted_message)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(decrypted_message)
                logging.info(f"Decrypted message saved to {args.output}")

        elif args.encrypt:
            if not args.message:
                logging.error("Message is required for encryption (-e).")
                return

            logging.info("Encrypting the message...")
            encrypted_message = encrypt_message(args.message, args.password)

            logging.info("Encryption successful.")
            print("Encrypted Message:", encrypted_message)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(encrypted_message)
                logging.info(f"Encrypted message saved to {args.output}")

        elif args.decrypt:
            if not args.message:
                logging.error("Message is required for decryption (-d).")
                return

            logging.info("Decrypting the message...")
            decrypted_message = decrypt_message(args.message, args.password)

            logging.info("Decryption successful.")
            print("Decrypted Message:", decrypted_message)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(decrypted_message)
                logging.info(f"Decrypted message saved to {args.output}")

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        logging.error(traceback.format_exc())


if __name__ == "__main__":
    main()
