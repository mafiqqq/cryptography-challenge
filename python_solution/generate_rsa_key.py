"""
1. Application to generate an RSA key pair, key size = 2048 bits (Standard Java library can be used to generate all keys and hashes).
"""
import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair():
    """Generate RSA Key Pair
    
    Args:
        None

    Returns:
        None: Function perform generation of RSA Key pair and save to file or exit on error
    """
    try:
        # Generate a private key and choose a commonly used e value (3,17,65537)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Extract the public key from private key
        public_key = private_key.public_key()

        # Serialization private key to PEM format
        private_pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        )

        # Serialization public key to PEM format
        public_pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Save keys to files
        try:
            os.makedirs('output_files', exist_ok=True)

            public_key_path = 'output_files/public_key.pem'
            private_key_path = 'output_files/private_key.pem'
            if os.path.exists(public_key_path):
                os.remove(public_key_path)
            
            if os.path.exists(private_key_path):
                os.remove(private_key_path)

            with open(private_key_path, 'wb') as f:
                f.write(private_pem)

            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            return private_key, public_key

        except PermissionError as e:
            print(f"Permission error when writing key file: {e}", sys.stderr)
        except IOError as e:
            print(f"I/O error when writing key file: {e}", sys.stderr) 

    except Exception as e:
        print(f"Unexpected error during RSA key generation: {e}", sys.stderr)


if __name__ == "__main__":
    print("Generating RSA Key-pair with 2048-bit key size")
    generate_rsa_key_pair()
    print("Successfully generated public key and private key")

