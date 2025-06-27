# 3. Application that will encrypt and decrypt the file using the RSA key pair generated.
import argparse
import sys
from cryptography.hazmat.primitives import serialization

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
    try:
        # Load the public key
        public_key = load_public_key(public_key_file)

        # Generate a 
    except Exception as e:
        print(f'')


def decrypt_file():
    print('a')


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