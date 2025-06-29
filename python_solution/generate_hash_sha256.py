"""
2. Application to generate SHA-256 hash of the attached file. No signing is needed. Just print hash in HEX encoding to standard output.
"""
import hashlib
from sys import stderr

def calculate_hash(file_path, chunk_size=65536):
    """Calculate the hash of the input file
    
    Args:
        file_path (str): Path to the input_file need to generate the hash
        chunk_size (int): Chunk size to read the input_file by chunk

    Returns:
        None: Function perform hash generation and print in HEX format or exit on error
    """
    sha256 = hashlib.sha256()

    try:
        # Open file and read in chunks for better memory management
        with open(file_path, "rb") as f:
            while byte_chunk := f.read(chunk_size):
                sha256.update(byte_chunk)
        
        print(sha256.hexdigest())

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=stderr)

if __name__ == "__main__":
    calculate_hash("AMD image file.JPG")