# PRISM: USB-Encryption

## Objective

The PRISM USB Encryption project aimed to develop a Python-based tool for secure file protection on portable storage devices. The focus was on implementing cryptographic methods to safeguard sensitive data while providing a user-friendly command-line interface for key generation, file encryption, and decryption. This project enhanced my understanding of cryptography principles, file system operations, and secure coding practices, simulating real-world data protection scenarios in a portable storage context.


### Skills Learned

- Cryptographic implementation using Python's Fernet library
- File and directory manipulation in Python
- Command-line interface design with argparse
- Error handling and exception management
- Basic key management for encryption
- Recursive file processing


### Tools Used

- Python for developing the core encryption and decryption functionality.
- Cryptography library (Fernet) for implementing secure encryption algorithms.
- Command-line interface (CLI) for user interaction and script execution.
- OS module for file system navigation and manipulation.
- Argparse module is used to parse command-line arguments and create a user-friendly interface.



# Steps

## Installation
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/your-username/repo-name.git
   cd repo-name
   
2. Install the required dependencies
   ```bash
   pip install cryptography

## Generating an Encryption Key

  Before encrypting or decrypting any files, you need to generate a secure encryption key. This key will be stored in a file called secret.key, which must be kept safe, as it's required to decrypt   the files.

To generate a new encryption key:

  ```bash
  python PRISM.py generate_key
  ```

This will create a file secret.key in the same directory.

## Encrypting Files and Filenames
   
  Once you have generated the encryption key, you can encrypt all files and filenames in a specified directory (e.g., your USB drive).

To encrypt files:

```bash
python PRISM.py encrypt <path_to_directory>
```
Replace <path_to_directory> with the actual path to the directory you want to encrypt (e.g., the path to your USB drive).


## Decrypting Files and Filenames
   
  To decrypt the files and restore the filenames, you will need to use the same key that was used for encryption (secret.key).

To decrypt files:

```bash
python PRISM.py decrypt <path_to_directory>
```
Again, replace <path_to_directory> with the actual path to the directory you want to decrypt.

