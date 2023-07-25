# perserve_evidence.py
import os
import shutil
import hashlib
import logging
import datetime
import threading
import zipfile
import pyAesCrypt

# Configuration
SOURCE_EVIDENCES = [
    {"path": "path/to/file.txt", "type": "file"},
    {"path": "path/to/directory", "type": "directory"},
    # Add more evidence entries as needed
]

DESTINATION_DIRECTORY = "path/to/destination"
FILE_EXTENSIONS_TO_PRESERVE = [".txt", ".log"]

# Advanced Configuration
BUFFER_SIZE = 64 * 1024  # 64KB buffer size for file encryption
ENCRYPTION_PASSWORD = "YourEncryptionPassword"
SIGNATURE_KEY = "YourSignatureKey"

def calculate_checksum(file_path):
    # Calculate SHA256 checksum of a file
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(BUFFER_SIZE), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def preserve_file(source_path, destination_directory):
    # Copy the file to the destination directory
    destination_file_path = os.path.join(destination_directory, os.path.basename(source_path))
    shutil.copy2(source_path, destination_file_path)

    # Calculate and record the SHA256 checksum
    checksum = calculate_checksum(destination_file_path)

    # Log the preservation of the file
    logging.info(f"Preserved {source_path} (Checksum: {checksum})")

    return {"File": os.path.basename(source_path), "Checksum": checksum}

def preserve_directory(source_path, destination_directory):
    # Create a zip archive of the directory
    archive_file_name = os.path.basename(source_path) + ".zip"
    archive_file_path = os.path.join(destination_directory, archive_file_name)

    with zipfile.ZipFile(archive_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(source_path):
            for file in files:
                if file.endswith(tuple(FILE_EXTENSIONS_TO_PRESERVE)):
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, source_path))

    # Calculate and record the SHA256 checksum of the archive
    checksum = calculate_checksum(archive_file_path)

    # Log the preservation of the archive
    logging.info(f"Preserved {source_path} (Checksum: {checksum})")

    return {"File": archive_file_name, "Checksum": checksum}

def encrypt_file(file_path, password):
    # Encrypt a file using AES encryption
    encrypted_file_path = file_path + ".aes"
    with open(file_path, "rb") as f_in:
        with open(encrypted_file_path, "wb") as f_out:
            pyAesCrypt.encryptStream(f_in, f_out, password, BUFFER_SIZE)
    os.remove(file_path)  # Remove the original unencrypted file
    return encrypted_file_path

def sign_data(data, key):
    # Create a digital signature of data using HMAC-SHA256
    import hmac
    signature = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    return signature

def preserve_evidence(source_evidence):
    # Create the destination directory if it does not exist
    if not os.path.exists(DESTINATION_DIRECTORY):
        os.makedirs(DESTINATION_DIRECTORY)

    # Initialize logging
    log_file = os.path.join(DESTINATION_DIRECTORY, "preservation_log.txt")
    logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Record preservation process start in the log
    logging.info("Preservation process started.")

    preserved_files = []

    try:
        for evidence in source_evidence:
            source_path = evidence["path"]
            evidence_type = evidence["type"]

            if evidence_type == "file":
                preserved_files.append(preserve_file(source_path, DESTINATION_DIRECTORY))
            elif evidence_type == "directory":
                preserved_files.append(preserve_directory(source_path, DESTINATION_DIRECTORY))

        # Encrypt preserved files
        for preserved_file in preserved_files:
            file_path = os.path.join(DESTINATION_DIRECTORY, preserved_file["File"])
            encrypted_file_path = encrypt_file(file_path, ENCRYPTION_PASSWORD)
            preserved_file["File"] = os.path.basename(encrypted_file_path)

        # Generate a digital signature for the preservation report
        preservation_report = "\n".join([f"{data['File']} (Checksum: {data['Checksum']})" for data in preserved_files])
        signature = sign_data(preservation_report, SIGNATURE_KEY)

        # Record preservation process completion in the log
        logging.info("Preservation process completed.")
    except Exception as e:
        # Log any encountered errors
        logging.error(f"Error during preservation process: {str(e)}")

def main():
    preserve_evidence(SOURCE_EVIDENCES)

if __name__ == "__main__":
    main()
