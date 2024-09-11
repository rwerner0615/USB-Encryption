import os
from cryptography.fernet import Fernet
import base64

def show_instructions():
    # Displays instructions for the user on how to use the program.
    print(r"""
     ________  ________  ___  ________  _____ ______      
    |\   __  \|\   __  \|\  \|\   ____\|\   _ \  _   \    
    \ \  \|\  \ \  \|\  \ \  \ \  \___|\ \  \\\__\ \  \   
     \ \   ____\ \   _  _\ \  \ \_____  \ \  \\|__| \  \  
      \ \  \___|\ \  \\  \\ \  \|____|\  \ \  \    \ \  \ 
       \ \__\    \ \__\\ _\\ \__\____\_\  \ \__\    \ \__\
        \|__|     \|__|\|__|\|__|\_________\|__|     \|__|
                                \|_________|              

    USB Encryption/Decryption Tool

    Instructions:
    1. Press 1 to encrypt files and file names in a directory.
    2. Press 2 to decrypt files and file names in a directory.
    3. Press 3 to generate a new encryption key.
    0. Press 0 to exit.

""")


def generate_key():
    # Generate a new Fernet key
    key = Fernet.generate_key()
    # Save the key to a file named 'secret.key'
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to 'secret.key'")

def load_key():
    # Load the encryption key from 'secret.key'
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("Error: 'secret.key' not found. Generate a key first.")
        exit(1)

def encrypt_file(file_path, key):
    # Encrypt the file content with the provided key
    f = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(file_path, key):
    # Decrypt the file content with the provided key
    f = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
    except Exception as e:
        print(f"Error decrypting {file_path}: {str(e)}")

def encrypt_filename(filename, key):
    # Encrypt the file name (excluding extension) using the provided key
    f = Fernet(key)
    name, ext = os.path.splitext(filename)
    encrypted_name = base64.urlsafe_b64encode(f.encrypt(name.encode())).decode()
    return encrypted_name + ext

def decrypt_filename(encrypted_filename, key):
    # Decrypt the file name (excluding extension) using the provided key
    f = Fernet(key)
    encrypted_name, ext = os.path.splitext(encrypted_filename)
    try:
        decrypted_name = f.decrypt(base64.urlsafe_b64decode(encrypted_name)).decode()
        return decrypted_name + ext
    except Exception as e:
        print(f"Error decrypting filename {encrypted_filename}: {str(e)}")
        return encrypted_filename

def process_directory(directory, key, decrypt=False):
    # Encrypt or decrypt all files and file names in the specified directory
    print(f"{'Decryption' if decrypt else 'Encryption'} in progress...")
    files_processed = 0

    # Define patterns or extensions to skip
    skip_patterns = ['.dat', '.sys', '.log']  # Add more patterns if needed

    for root, dirs, files in os.walk(directory):
        # Skip system directories like 'System Volume Information'
        dirs[:] = [d for d in dirs if d.lower() not in {'system volume information'}]
        for file in files:
            # Skip files with certain patterns or extensions
            if any(file.lower().endswith(pattern) for pattern in skip_patterns):
                continue

            file_path = os.path.join(root, file)
            try:
                if decrypt:
                    # Decrypt files and their names
                    decrypt_file(file_path, key)
                    decrypted_name = decrypt_filename(os.path.basename(file_path), key)
                    new_file_path = os.path.join(root, decrypted_name)
                    # Check if the destination file already exists
                    if os.path.exists(new_file_path):
                        print(f"File already exists, skipping: {new_file_path}")
                    else:
                        os.rename(file_path, new_file_path)
                else:
                    # Encrypt files and their names
                    encrypted_name = encrypt_filename(file, key)
                    new_file_path = os.path.join(root, encrypted_name)
                    encrypt_file(file_path, key)
                    # Check if the destination file already exists
                    if os.path.exists(new_file_path):
                        print(f"File already exists, skipping: {new_file_path}")
                    else:
                        os.rename(file_path, new_file_path)
                
                files_processed += 1
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")

    print(f"{'Decryption' if decrypt else 'Encryption'} completed. Total files processed: {files_processed}")

def main():
    # Show instructions once at the start
    show_instructions()

    while True:
        choice = input("Enter your choice (1 for Encrypt, 2 for Decrypt, 3 for Generate Key, 0 to Exit): ")

        if choice == "0":
            print("Exiting...")
            break
        elif choice == "3":
            # Generate a new encryption key
            generate_key()
        elif choice in ["1", "2"]:
            # Load the encryption key
            key = load_key()
            directory = input("Enter the directory path: ")
            if choice == "1":
                # Encrypt files and file names
                process_directory(directory, key)
            elif choice == "2":
                # Decrypt files and file names
                process_directory(directory, key, decrypt=True)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
