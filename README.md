# Secure File Guard

The Secure File Guard is a Python-based encryption and decryption tool that enhances the confidentiality of sensitive data through strong encryption mechanisms.

## Features
- Encryption/Decryption: Easily encrypt and decrypt files with a password.
- Enhanced Security: Utilizes ChaCha20 encryption and bcrypt hashing for additional security measures.
- Multiple File Support: Encrypt or decrypt multiple files at once.

## Usage
### Encryption
To encrypt a file or files:

```bash
python secure_file_guard.py --encrypt -input <file_name> -password <your_password> [-secure]
```

### Decryption
To decrypt a file or files:

```bash
python secure_file_guard.py --decrypt -input <file_name> -password <your_password>
```
- input: Specify the file name or “all” to decrypt all files.
- password: Enter the password used for encryption.

How It Works
The tool uses ChaCha20 encryption to secure the data and bcrypt for password hashing, providing a robust encryption method to safeguard your files.

Requirements
- Python 3.x
- Crypto library (`pip install pycryptodome`)
- bcrypt library (`pip install bcrypt`)

Notes
- Ensure you have the required permissions to access and modify the specified files.
- Always keep your password secure and do not share it with unauthorized users.

###Contributors
[Jirka Husak]

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

