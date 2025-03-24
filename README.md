
# StegaCrypt

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.7%2B-brightgreen.svg)](https://www.python.org/)

**StegaCrypt** is a CLI tool for securely hiding messages in images using steganography, combined with robust encryption and decryption features. It allows users to securely share sensitive data by embedding it into image files.

---

## Features

- **Message Encryption**: Encrypt messages with a password before hiding them.
- **Image Steganography**: Embed encrypted messages into images without altering their appearance.
- **Message Decryption**: Extract and decrypt hidden messages from stego images.
- **Secure Communication**: Ensures confidentiality of messages through encryption and steganography.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/StegaCrypt.git
   cd StegaCrypt
   ```

2. Install the package:
   ```bash
   pip install .
   ```

3. Verify the installation:
   ```bash
   stegacrypt --help
   ```

---

## Usage

### Store (Encrypt and Hide a Message in an Image)
```bash
stegacrypt -s -m "This is a secret message" -p "password123" -i input_image.png -o stego_image.png
```
- `-s`: Store mode.
- `-m`: The message to hide.
- `-p`: Password for encryption.
- `-i`: Input image file.
- `-o`: Output stego image file (optional; defaults to `stego_image.png`).

### Read (Extract and Decrypt a Message from an Image)
```bash
stegacrypt -r -p "password123" -i stego_image.png -o output.txt
```
- `-r`: Read mode.
- `-p`: Password for decryption.
- `-i`: Input stego image file.
- `-o`: Output file for the extracted message (optional; defaults to displaying the message in the terminal).

### Encrypt Only (Without Hiding in an Image)
```bash
stegacrypt -e -m "This is a secret message" -p "password123" -o encrypted.txt
```
- `-e`: Encrypt mode.
- `-m`: Message to encrypt.
- `-p`: Password for encryption.
- `-o`: Output file for the encrypted message.

### Decrypt Only (Without Extracting from an Image)
```bash
stegacrypt -d -m "EncryptedMessageHere" -p "password123" -o decrypted.txt
```
- `-d`: Decrypt mode.
- `-m`: Encrypted message.
- `-p`: Password for decryption.
- `-o`: Output file for the decrypted message.

---

## Examples

### Hiding a Secret Message
```bash
stegacrypt -s -m "Hello, this is a top-secret message!" -p "securepassword" -i cat.png -o cat_stego.png
```

### Reading the Hidden Message
```bash
stegacrypt -r -p "securepassword" -i cat_stego.png
```

### Encrypting a Message
```bash
stegacrypt -e -m "Confidential data" -p "mykey" -o encrypted.txt
```

### Decrypting a Message
```bash
stegacrypt -d -m "EncryptedMessageHere" -p "mykey"
```

---

## Requirements

- Python 3.7+
- Libraries:
  - [Click](https://pypi.org/project/click/)
  - [Cryptography](https://pypi.org/project/cryptography/)

---

## How It Works

1. **Encrypting Messages**: Messages are encrypted using a password to provide confidentiality.
2. **Hiding Data**: Encrypted messages are embedded into the least significant bits of pixel data in the image.
3. **Extracting Data**: The hidden data is extracted from the image.
4. **Decrypting Messages**: Extracted data is decrypted using the same password.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please fork the repository and create a pull request.

1. Fork the project.
2. Create your feature branch: `git checkout -b feature-name`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

---

## Author

**Team Cyfer Trace**

For any queries or issues, feel free to contact us via the [Issues](https://github.com/your-repo/StegaCrypt/issues) page.
