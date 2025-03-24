import cv2
import numpy as np
import logging
import base64

logging.basicConfig(level=logging.INFO)

def embed_data_in_image(image_path, encrypted_message, output_path):
    import numpy as np
    import cv2

    # Convert the message into binary format
    message_binary = ''.join(format(ord(c), '08b') for c in encrypted_message)

    # Add a 16-bit length prefix
    message_length = len(message_binary)
    length_prefix = format(message_length, '016b')  # 16-bit binary length
    final_message_binary = length_prefix + message_binary

    # Load the image
    image = cv2.imread(image_path)
    flat_image = image.flatten()

    # Check capacity
    if len(flat_image) < len(final_message_binary):
        raise ValueError("Image does not have enough capacity to embed the data.")

    # Embed data into the image
    for i, bit in enumerate(final_message_binary):
        flat_image[i] = (flat_image[i] & ~1) | int(bit)  # Set the least significant bit

    # Save the stego image
    stego_image = flat_image.reshape(image.shape)
    cv2.imwrite(output_path, stego_image)
    logging.info(f"Stego image saved to {output_path}")



def extract_data_from_image(image_path):
    import numpy as np
    import cv2

    # Load the stego image
    stego_image = cv2.imread(image_path)
    flat_image = stego_image.flatten()

    # Extract the first 16 bits (length prefix)
    length_binary = ''.join(str(flat_image[i] & 1) for i in range(16))
    message_length = int(length_binary, 2)

    # Extract the message using the length
    message_binary = ''.join(str(flat_image[i] & 1) for i in range(16, 16 + message_length))

    # Convert binary to text
    message = ''.join(chr(int(message_binary[i:i + 8], 2)) for i in range(0, len(message_binary), 8))
    return message
