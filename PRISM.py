from cryptography.fernet import Fernet
import os
import argparse
import base64

def show_instructions():
    """
    Displays instructions for the user on how to use the program.
    """
    print("""
    USB Encryption/Decryption Tool
    
    Instructions:
    - To generate a new encryption key: 
      python PRISM.py generate_key
    
    - To encrypt all files and file names in a directory (e.g., your USB drive):
      python PRISM.py encrypt <path_to_your_directory>
    
    - To decrypt all files and file names in a directory (e.g., your USB drive):
      python PRISM.py decrypt <path_to_your_directory>
      
    Please ensure that the 'secret.key' file is in the same directory as the script 
    when encrypting or decrypting files.
    """)


def generate_key():
    # Generate a new Fernet key
    key = Fernet.generate_key()
    # Save the key to a file named 'secret.key'
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to 'secret.key'")

def load_key():
    try:
        # Attempt to read the key from the file
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        # If the key file is not found, print an error and exit
        print("Error: 'secret.key' not found. Generate a key first.")
        exit(1)

def encrypt_file(file_path, key):
    # Create a Fernet instance with the provided key
    f = Fernet(key)
    # Read the file content
    with open(file_path, "rb") as file:
        file_data = file.read()
    # Encrypt the file content
    encrypted_data = f.encrypt(file_data)
    # Write the encrypted content back to the file
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(file_path, key):
    # Create a Fernet instance with the provided key
    f = Fernet(key)
    # Read the encrypted file content
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    try:
        # Attempt to decrypt the file content
        decrypted_data = f.decrypt(encrypted_data)
        # Write the decrypted content back to the file
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
    except Exception as e:
        # If decryption fails, print an error message
        print(f"Error decrypting {file_path}: {str(e)}")

def encrypt_filename(filename, key):
    """
    Encrypts the file name (excluding extension) using the provided key.
    """
    f = Fernet(key)
    name, ext = os.path.splitext(filename)
    encrypted_name = base64.urlsafe_b64encode(f.encrypt(name.encode())).decode()
    return encrypted_name + ext

def decrypt_filename(encrypted_filename, key):
    """
    Decrypts the file name (excluding extension) using the provided key.
    """
    f = Fernet(key)
    encrypted_name, ext = os.path.splitext(encrypted_filename)
    try:
        decrypted_name = f.decrypt(base64.urlsafe_b64decode(encrypted_name)).decode()
        return decrypted_name + ext
    except Exception as e:
        print(f"Error decrypting filename {encrypted_filename}: {str(e)}")
        return encrypted_filename

def process_directory(directory, key, decrypt=False):
    """
    Encrypts or decrypts all files in the specified directory, including file names.
    """
    print(f"{'Decryption' if decrypt else 'Encryption'} in progress...")
    files_processed = 0

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if decrypt:
                    decrypt_file(file_path, key)
                    decrypted_name = decrypt_filename(os.path.basename(file_path), key)
                    os.rename(file_path, os.path.join(root, decrypted_name))
                else:
                    encrypted_name = encrypt_filename(file, key)
                    new_file_path = os.path.join(root, encrypted_name)
                    encrypt_file(file_path, key)
                    os.rename(file_path, new_file_path)
                
                files_processed += 1
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")

    print(f"{'Decryption' if decrypt else 'Encryption'} completed. Total files processed: {files_processed}")

def main():
    
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt USB files")
    parser.add_argument("mode", choices=["encrypt", "decrypt", "generate_key"], help="Mode: encrypt, decrypt, or generate_key", nargs='?')
    parser.add_argument("path", nargs='?', help="Path to the USB drive")
    args = parser.parse_args()

    if args.mode is None:
        show_instructions()
        return

    if args.mode == "generate_key":
        generate_key()
        return

    if not args.path and args.mode in ["encrypt", "decrypt"]:
        print("Error: Path is required for encrypt and decrypt modes.")
        parser.print_help()
        return

    try:
        # Load the encryption key
        key = load_key()
        if args.mode == "encrypt":
            process_directory(args.path, key)
        elif args.mode == "decrypt":
            process_directory(args.path, key, decrypt=True)
    except Exception as e:
        # If an unexpected error occurs, print an error message
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
