# utils.py
import hashlib
import os
import shutil
import logging
import gzip
import pyAesCrypt

# Constants
BUFFER_SIZE = 64 * 1024  # 64KB buffer size for file encryption
ENCRYPTION_PASSWORD = "YourEncryptionPassword"

def calculate_sha256_checksum(file_path):
    # Calculate the SHA256 checksum of a file
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(BUFFER_SIZE), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def create_directory(directory_path):
    # Create a directory if it does not exist
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

def encrypt_file(input_file, output_file, password):
    # Encrypt a file using AES encryption
    with open(input_file, "rb") as f_in:
        with open(output_file, "wb") as f_out:
            pyAesCrypt.encryptStream(f_in, f_out, password, BUFFER_SIZE)

def decrypt_file(input_file, output_file, password):
    # Decrypt a file previously encrypted with AES encryption
    with open(input_file, "rb") as f_in:
        with open(output_file, "wb") as f_out:
            pyAesCrypt.decryptStream(f_in, f_out, password, BUFFER_SIZE)

def compress_file(input_file, output_file):
    # Compress a file using gzip compression
    with open(input_file, "rb") as f_in:
        with gzip.open(output_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

def decompress_file(input_file, output_file):
    # Decompress a file previously compressed with gzip compression
    with gzip.open(input_file, "rb") as f_in:
        with open(output_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

def setup_logging(log_file_path):
    # Set up logging to write to both console and log file
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create a file handler for writing logs to the specified file
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)

    # Create a console handler for writing logs to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create a formatter and attach it to the handlers
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger = logging.getLogger()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def handle_error(func):
    # A decorator to handle exceptions and log errors
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            return None
    return wrapper
