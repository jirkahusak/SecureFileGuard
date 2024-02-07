# Secure File Guard
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

The Secure File Guard is a Python-based encryption, decryption and secure deletion tool that enhances the confidentiality of sensitive data through strong encryption mechanisms.

## Features
- Encryption/Decryption: Easily encrypt and decrypt files with a password.
- Deletion: Securely deletes files to not be recoverable by forensic methods in it's original form.
- Enhanced Security: Utilizes ChaCha20 encryption and bcrypt hashing for additional security measures.
- Multiple File Support: Encrypt or decrypt multiple files at once.

## Usage
### Encryption
To encrypt a file or files:

```bash
python SecureFileGuard.py -encrypt -input <file_name> -password <your_password> [-secure]
```
- input: Specify the file name or 'all' to delete all files within the current working directory.
- password: Enter the password used for encryption.

### Decryption
To decrypt a file or files:

```bash
python SecureFileGuard.py -decrypt -input <file_name> -password <your_password>
```
- input: Specify the file name or 'all' to delete all files within the current working directory.
- password: Enter the password used for encryption.

### -secure Flag

- The `--secure` flag enhances security.
- When used during encryption, it doesn’t hash the password or store it in the metadata.
- This means that the password must be entered correctly during decryption.
- There’s no stored hash to compare it against.
- This provides an additional layer of security.

### Deletion
To securely delete a file or files:

```bash
python secure_file_guard.py -delete -input <file_name>
```
- input: Specify the file name or 'all' to delete all files within the current working directory.

### Requirements
- Python 3.x
- Crypto library (`pip install pycryptodome`)
- bcrypt library (`pip install bcrypt`)

#### Notes
- Ensure you have the required permissions to access and modify the specified files.
- Always keep your password secure and do not share it with unauthorized users.

### Contributors

[@jirkahusak](https://www.github.com/jirkahusak)

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
