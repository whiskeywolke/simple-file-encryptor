#!/usr/bin/env python3

import base64
import concurrent
import getpass
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_replace(folder: str, file_name: str, fernet: Fernet):
    target_file_path_read = os.path.join(folder, file_name)

    with open(target_file_path_read, 'rb') as file:
        original = file.read()

    encrypted_name = fernet.encrypt(bytes(file_name, 'utf-8')).decode('utf-8')
    target_file_path_write = os.path.join(folder, encrypted_name)
    encrypted_data = fernet.encrypt(original)

    with open(target_file_path_write, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
        os.remove(target_file_path_read)


def decrypt_replace(folder: str, file_name: str, fernet: Fernet):
    target_file_path_read = os.path.join(folder, file_name)
    with open(target_file_path_read, 'rb') as enc_file:
        encrypted = enc_file.read()

    decrypted_name = fernet.decrypt(bytes(file_name, 'utf-8')).decode('utf-8')
    target_file_path_write = os.path.join(folder, decrypted_name)
    decrypted = fernet.decrypt(encrypted)

    with open(target_file_path_write, 'wb') as dec_file:
        dec_file.write(decrypted)
        os.remove(target_file_path_read)


def main(target_folder="data"):
    p = getpass.getpass(prompt='Encyption Key:')
    password = bytes(p, 'utf-8')
    salt = b"salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # using the generated key
    fernet = Fernet(key)

    files = os.listdir(target_folder)
    encrypt = True
    for f in files:
        if "=" in f:
            encrypt = False
    if encrypt:
        print("Encrypting...")
    else:
        print("Decrypting...")

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for target_file_name in files:
            if encrypt:
                futures.append(executor.submit(encrypt_replace, target_folder, target_file_name, fernet))
            else:
                futures.append(executor.submit(decrypt_replace, target_folder, target_file_name, fernet))
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res is not None:
                    print(res)
            except requests.ConnectTimeout:
                print("ConnectTimeout.")

    execution_time = (time.time() - start_time)
    print('Execution time in seconds: ' + str(execution_time))


if __name__ == "__main__":
    main(sys.argv[1])
