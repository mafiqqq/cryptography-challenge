# 3. Application that will encrypt and decrypt the file using the RSA key pair generated.
import argparse
import sys
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

def main():
    parser = argparse.ArgumentParser(description='File encryption or decryption using RSA key pair')

    # Create subparsers to separate encrypt/decrypt commands
    subparser = parser.add_subparsers(dest='command')

    # Encrypt command
    encrypt_parser = subparser.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('-f', '--file', required=True, help='File to be encrypted')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Public key file')

    # Decrypt command
    decrypt_parser = subparser.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('-f', '--file', required=True, help='File to be decrypted')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Private key file')

    args = parser.parse_args()

    if args.command == 'encrypt':
        encrypt_file(args.file, args.key)
    elif args.command == 'decrypt':
        decrypt_file(args.file, args.key)
    else:
        parser.print_help()
        sys.exit(1)


def encrypt_file(input_file, public_key_file):
    # Encrypt input_file with AES using random generated key 
    # then encrypt AES key with the public key
    try:
        # Load the public key
        public_key = load_public_key(public_key_file)

        # Generate random AES key
        aes_key = os.urandom(32) # 256-bit

        # Using AES encryption algorithm with CBC mode of operation, generate random Initialization Vector (IV)
        # IV - Random values that ensures each encryption with same key produces different ciphertext
        iv = os.urandom(16)  # 128-bit

        # Read the input file
        with open(input_file, 'rb') as f:
            file_data = f.read()

        # Encrypt file_data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext_aes = encryptor.update(file_data) + encryptor.finalize()
        tag = encryptor.tag



        # Encrypt the AES key with RSA public_key
        # use OAEP (Optimal Asymmetric Encryption Padding) that provides probabilistic encryption
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Output file for encrypted input_file
        encrypted_file_data = {
            'encrypted_aes_key': encrypted_aes_key,

        }

        return encrypted_aes_key, iv, ciphertext_aes

    except FileNotFoundError as e:
        print(f'Error: File not found : {e}', sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'Error: Encryption failed : {e}', sys.stderr)
        sys.exit(1)


def decrypt_file(encrypted_aes_key, iv, private_key_file):
    # Decrypt the AES key with the RSA private_key
    # then decrypt the input_file with the decrypted AES key
    
    try:
        # Load the private_key
        private_key = load_private_key(private_key_file)
        
        # Read the encrypted file

        # Decrypt AES key with private_key
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the input_file with decrypted_aes_key
        cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext_aes) + decryptor.finalize()
        decrypted_input_file = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_input_file
    
    except Exception as e:
        pass

def load_public_key(key_file):
    try:
        with open(key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        
        return public_key
    except Exception as e:
        print(f"Error loading public key from file {key_file}: {e}", file=sys.stderr)


def load_private_key(key_file):
    try:
        with open(key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        return private_key
    except Exception as e:
        print(f"Error loading public key from file {key_file}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()