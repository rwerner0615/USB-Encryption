# PRISM: USB-Encryption v2

## Objective

The **PRISM USB Encryption v2** project builds on the original by introducing performance optimizations and enhanced user experience features. In addition to the core encryption and decryption functionalities, v2 incorporates improvements in key management, advanced error handling, and batch processing for larger datasets. These updates enhance usability, efficiency, and compatibility with modern file systems, making the tool more robust for real-world applications.

### Key Updates in PRISM v2

- **Improved Command-Line Interface**: Clearer feedback during encryption/decryption processes, with support for batch operations across large file sets.
- **Performance Optimizations**: Faster processing times, especially with large directories and USB drives.
- **Enhanced Error Handling**: Better management of exceptions for incompatible file types or system errors during recursive file operations.
- **File and Folder Integrity**: More efficient preservation of directory structure during encryption and decryption.
- **Security Enhancements**: Updated cryptographic practices for stronger data protection.

### Skills Enhanced

- Advanced cryptographic methods using Python's Cryptography library
- Optimized recursive file processing and directory structure management
- Batch processing for large data sets
- Robust command-line interface design with detailed user feedback
- Comprehensive error handling for better system stability

### Tools Used

- **Python** for implementing core functionality
- **Cryptography library (Fernet)** for secure encryption and decryption
- **Command-line interface (CLI)** for a user-friendly experience
- **OS module** for refined file system operations and directory management
- **Argparse module** for efficient command parsing and batch operations

# Steps

## Installation
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/your-username/repo-name.git
   cd repo-name
   
2. Install the required dependencies
   ```bash
   pip install cryptography

3. Run PRISMv2.py and it will walk you through the rest
   ```bash
   python PRISMv2.py
<br />


# PRISM: USB-Encryption (Outdated)

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

