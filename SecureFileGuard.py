import os
import sys
from Crypto.Cipher import ChaCha20
import hashlib
import bcrypt
import argparse

def main():
    parser = argparse.ArgumentParser(description='Decryption tool that allows users to protect the confidentiality of their sensitive data.')
    encrypt_decrypt_group = parser.add_mutually_exclusive_group(required=True)
    encrypt_decrypt_group.add_argument('-encrypt', '--encrypt', help='Encryption of file/s', action='store_true')
    encrypt_decrypt_group.add_argument('-decrypt', '--decrypt', help='Encryption of file/s.', action='store_true')
    parser.add_argument('-input', '--input', help='The input file/s.', required=True)
    parser.add_argument('-password', '--password', help='The password for encryption/decryption.', required=True)
    parser.add_argument('-secure', '--secure', help='Choose if you want to have additional security.', action='store_true')

    args = parser.parse_args()

    all_files = list_all_files()
     

    if args.input == "all":
        file = all_files
    else:
        wanted_file = args.input
        for i in all_files:
            if i == wanted_file:
                file = i
    
    if not args.password:
        print("You need to enter a password. Please try again.")
        sys.exit(1)
    else:
        password = args.password

    if args.secure:
        secure = True
    else:
        secure = False

    
    if args.encrypt:
        function = "encrypt"

    if args.decrypt:
        function = "decrypt"

    if not args.encrypt and not args.decrypt:
        print("You must choose either encryption or decryption. Please try again.")
        sys.exit(1)

    if function == "encrypt":

        separator = b'|||'

        result = hashing(password, secure)


        if secure:
            if result is not None:
                key = result
                hashed_pass = None
                salt = None
        else:
            if result is not None:
                key, hashed_pass, salt = result
                metadata = hashed_pass + separator + salt
            

        if isinstance(file, list):
            for i in file:
                try:
                    read_data = read_binary(i)
                    encrypted, nonce = encryption(key, read_data)

                    if hashed_pass and salt is not None:
                        data_to_write = encrypted + separator + nonce + separator + metadata
                    else:
                        data_to_write = encrypted + separator + nonce

                    write_binary(i, data_to_write)

                except Exception as e:
                    print(f"An error occurred: {str(e)}")
                    sys.exit(1)
                
                print(f"Encrypted {i}")

        else:
            try: 
                read_data = read_binary(file)
                encrypted, nonce = encryption(key, read_data)

                if hashed_pass and salt is None:
                    data_to_write = encrypted + separator + nonce + separator + metadata
                else:
                    data_to_write = encrypted + separator + nonce
                   
                write_binary(file, data_to_write)
            except Exception as e:
                print(f"An error occurred: {str(e)}")
                sys.exit(1)

            print(f"Encrypted {file}")
    else:

        key = hashing(password, True)
        separator = b'|||'
        

        if isinstance(file, list):
            for i in file:
                read_data = read_binary(i)
                sections = read_data.split(separator)
                data = sections[0]
                metadata_nonce = sections[1]

                if(len(sections) > 2):
                    metadata_password = sections[2]
                    metadata_salt = sections[3]

                    password_to_check = bcrypt.hashpw(password.encode('utf-8'), metadata_salt)

                    if password_to_check != metadata_password:
                        print("Your password doesn't match your encryption password.")
                        sys.exit(1)

                decrypted = decryption(key, data, metadata_nonce)
                write_binary(i, decrypted)
                print(f"Decrypted {i}")
        else:
            read_data = read_binary(file)
            sections = read_data.split(separator)
            data = sections[0]
            metadata_nonce = sections[1]

            if(len(sections) > 2):
                metadata_password = sections[2]
                metadata_salt = sections[3]

                password_to_check = bcrypt.hashpw(password.encode('utf-8'), metadata_salt)

                if password_to_check != metadata_password:
                    print("Your password doesn't match your encryption password.")
                    sys.exit(1)
                
            decrypted = decryption(key, data, metadata_nonce)
            write_binary(file, decrypted)
            print(f"Decrypted {file}")


def read_binary(file_name):
    try:
        with open(file_name, 'rb') as file:
            binary_data = file.read()
    except FileNotFoundError:
        print("Couldn't find a file.")
        binary_data = None

    return binary_data

def write_binary(file_name, binary):
    try:
        with open(file_name, 'wb') as file:
            file.write(binary)
    except FileNotFoundError:
        print("Couldn't find a file.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def hashing(input_password, secure):
    try:
        # Derives key from inputed password
        byte_input = input_password.encode('utf-8')
        hash_key = hashlib.sha256(byte_input)
        hashed_key = hash_key.hexdigest()
        #hashed_key = hashed_key[:32]
    except Exception as e:
        print(f"An error occurred with sha256: {str(e)}")
        return None
    if(secure == False):
        # If secure is set to False then it hashes the inputed password to store as a metadata
        try:
            salt = bcrypt.gensalt()
            hashed_pass = bcrypt.hashpw(input_password.encode('utf-8'), salt)
                
            return hashed_key, hashed_pass, salt
        except Exception as e:
            print(f"An error occurred with bcrypt: {str(e)}")
            return None
    else:
        return hashed_key

def list_all_files():
    try:
        # Takes the name of this file
        path_name = os.path.abspath(__file__)
        file_name = os.path.basename(path_name)
        # Creates list of files in working directory
        folder_path = os.path.dirname(__file__)
        file_list = [file for file in os.listdir(folder_path) if os.path.isfile (os.path.join(folder_path, file)) and file != file_name]
        return file_list
    except FileNotFoundError:
        print("The specified directory does not exist.")
        return []
    except PermissionError:
        print("You don't have permission to access the directory.")
        return []
     
def encryption(key, data):
    try:
        # Encrypt data with ChaCha20
        key_bytes = bytes.fromhex(key)
        cipher = ChaCha20.new(key=key_bytes)
        encrypted = cipher.encrypt(data)
    except Exception as e:
        print(f"An error has occurred with encryption: {str(e)}")
        return None
    return encrypted, cipher.nonce

def decryption(key, data, nonce):
    try:
        # Decrypt data with ChaCha20
        key_bytes = bytes.fromhex(key) 
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        decrypted = cipher.decrypt(data)
    except Exception as e:
        print(f"An error has occurred with decryption: {str(e)}")
        return None
    return decrypted    

if __name__ == '__main__':
    main()