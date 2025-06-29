# Cryptography Coding Challenge

A Cryptography Codding Challenge to test on the following aspect

1. Application to generate an RSA key pair, key size = 2048 bits.
2. Application to generate SHA-256 hash of the attached file. No signing is needed. Just print hash in HEX encoding to standard output.
3. Application that will encrypt and decrypt the file using the RSA key pair generated.

## Pre-requisites

- Python 3.6+
- Python Cryptography library

## Installation

1. Clone this repository
```bash
git clone <repository_url>
```

2. Install the required dependency
```bash
pip install cryptography
```

## Usage

### Generate RSA Key Pair
First, you need to generate RSA key pair
```bash
python generate_rsa_key.py
```
This will create:

- output_files/public_key.PEM
- output_files/private_key.PEM

> Note: `public_key.pem` and `private_key.pem` file have already been successfully created. You can run the script again and it will create a new RSA key-pair 

### Generate Hash (SHA-256)
Second, you can generate the hash (HEX) for the input file
```bash
python generate_hash_sha256.py
```
> Note: By default `AMD image file.JPG` will be used to generate hash SHA-256. 
### Create Encryption/Decryption of the input file
#### Encrypt a file
```bash
python file_encrypt_decrypt.py encrypt -f path/to/your/file -k output_files/public_key.pem
```
> Note: `encryption_ouput/encryption.json` file will be created after successfully encrypted. 
#### Decrypt a file
```bash
python file_encrypt_decrypt.py decrypt -f path/to/file/encryption_ouput/encryption.json -k output_files/private_key.pem
```

### Project Structure
```
project
│   README.md
└───python_solution
│   │   AMD image file.JPG
│   │   file_encrypt_decrypt.py
│   │   generate_hash_sha256.py
│   │   generate_rsa_key.py
└───────output_files
│   |   │   public_key.pem
│   |   │   private_key.pem
```
