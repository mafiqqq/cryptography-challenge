# 1. Application to generate an RSA key pair, key size = 2048 bits (Standard Java library can be used to generate all keys and hashes).
# RSA
# a. Select two large prime numbers p and q
# b. Calculate n = p x q 
# c. Calculate Phi(n) = (p-1) x (q-1)  -> Euler's totient function
# d. Choose e (public exponent) such as that 2 < e < Phi(n) and co-prime gcd(e, Phi(n)) = 1
# e. Calculate d (private exponent) such as that (e x d) mod Phi(n) = 1

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_key_pair():
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

            with open('output_files/private_key.pem', 'wb') as f:
                f.write(private_pem)

            with open('output_files/public_key.pem', 'wb') as f:
                f.write(public_pem)
            
            return private_key, public_key

        except PermissionError as e:
            print(f"Permission error when writing key file: {e}")
        except IOError as e:
            print(f"I/O error when writing key file: {e}") 

    except Exception as e:
        print(f"Unexpected error during key generation: {e}")


if __name__ == "__main__":
    print("Generating RSA Key-pair with 2048-bit key size")
    generate_rsa_key_pair()
    print("Successfully generated public key and private key")

