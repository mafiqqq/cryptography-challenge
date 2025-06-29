"""
3. Application that will encrypt and decrypt the file using the RSA key pair generated.
"""
import argparse
import sys
import os
import base64
import json
from pathlib import Path
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

        # Using AES encryption algorithm with GCM mode of operation, generate nonce for AES-GCM
        aes_nonce = os.urandom(12)  # 96-bit

        # Read the input file
        with open(input_file, 'rb') as f:
            input_data = f.read()

        # Create an AES-GCM cipher object
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_nonce), backend=default_backend())
        
        # Encrypt input_data
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(input_data) + encryptor.finalize()
        auth_tag = encryptor.tag

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

        # Extract extension of input_file
        filename = os.path.basename(input_file)
        file_extension = os.path.splitext(input_file)[1]

        # Output file for encrypted input_file
        encrypted_input_data = {
            'algorithm': 'RSA-OAEP + AES-256-GCM',
            'file_size': len(input_data),
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'aes_nonce': base64.b64encode(aes_nonce).decode('utf-8'),
            'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
            'encrypted_input': base64.b64encode(encrypted_data).decode('utf-8'),
            'filename': filename,
            'file_extension':  file_extension,
        }
        
        # Create output directory if does not exist
        output_path = Path('encryption_output')
        output_path.mkdir(exist_ok=True)

        output_file = f"{output_path}/encrypted.json"
        with open(output_file, 'w') as outfile:
            json.dump(encrypted_input_data, outfile, indent=2)
        
        print(f"File has been successfully encrypted: {output_file} ")
        return True

    except FileNotFoundError as e:
        print(f'Error: File not found : {e}', sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'Error: Encryption failed : {e}', sys.stderr)
        sys.exit(1)


def decrypt_file(encrypted_file_path, private_key_file):
    # Decrypt the AES key with the RSA private_key
    # then decrypt the input_file with the decrypted AES key
    
    try:
        # Load the private_key
        private_key = load_private_key(private_key_file)
        
        # Read the encrypted file
        with open(encrypted_file_path, 'r') as f:
            encrypted_data = json.load(f)

        # Decode the encrypted_data
        encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_aes_key'])
        aes_nonce = base64.b64decode(encrypted_data['aes_nonce'])
        auth_tag = base64.b64decode(encrypted_data['auth_tag'])
        encrypted_input = base64.b64decode(encrypted_data['encrypted_input'])

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
        cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(aes_nonce, auth_tag), backend=default_backend)
        decryptor = cipher.decryptor()
        
        decrypted_input_file = decryptor.update(encrypted_input) + decryptor.finalize()

        # Sanity check - Verify if file size are the same
        if (len(decrypted_input_file) != encrypted_data['file_size']):
            raise ValueError(f"File size mismatch - Decrypted file size: {len(decrypted_input_file)}, Encrypted file size: {encrypted_data['file_size']}")
        
        # Create output directory if does not exist
        output_path = Path('encryption_output')
        output_path.mkdir(exist_ok=True)

        # Write the decrypted input_file
        decrypted_file = f"{output_path}/decrypted_{encrypted_data['filename']}"
        with open(decrypted_file, 'wb') as f:
            f.write(decrypted_input_file)

        print(f"File has been successfully encrypted: {decrypted_file} ")
                
        return True
    
    except Exception as e:
        print(f'Error: Decryption failed : {e}', sys.stderr)
        sys.exit(1)

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