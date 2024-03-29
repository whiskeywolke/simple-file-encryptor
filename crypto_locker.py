#!/usr/bin/env python3

import base64
import concurrent
import getpass
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import argparse
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct


def encrypt(read_folder: str, out_folder:str, file_name: str, fernet: Fernet):
    target_file_path_read = os.path.join(read_folder, file_name)

    with open(target_file_path_read, 'rb') as file:
        original = file.read()

    encrypted_name = fernet.encrypt(bytes(file_name, 'utf-8')).decode('utf-8')
    target_file_path_write = os.path.join(out_folder, encrypted_name)
    encrypted_data = fernet.encrypt(original)

    with open(target_file_path_write, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt(read_folder: str, out_folder: str, file_name: str, fernet: Fernet):
    target_file_path_read = os.path.join(read_folder, file_name)
    with open(target_file_path_read, 'rb') as enc_file:
        encrypted = enc_file.read()

    decrypted_name = fernet.decrypt(bytes(file_name, 'utf-8')).decode('utf-8')
    target_file_path_write = os.path.join(out_folder, decrypted_name)
    decrypted = fernet.decrypt(encrypted)

    with open(target_file_path_write, 'wb') as dec_file:
        dec_file.write(decrypted)

def encrypt_streaming(read_folder: str, out_folder:str, file_name: str, fernet: Fernet, *, block = 1 << 16):
    fin = os.path.join(read_folder, file_name)
    encrypted_name = fernet.encrypt(bytes(file_name, 'utf-8')).decode('utf-8')
    fout = os.path.join(out_folder, encrypted_name)

    with open(fin, 'rb') as fi, open(fout, 'wb') as fo:
        while True:
            chunk = fi.read(block)
            if len(chunk) == 0:
                break
            enc = fernet.encrypt(chunk)
            fo.write(struct.pack('<I', len(enc)))
            fo.write(enc)
            if len(chunk) < block:
                break

def decrypt_streaming(read_folder: str, out_folder:str, file_name: str, fernet: Fernet):
    fin = os.path.join(read_folder, file_name)
    decrypted_name = fernet.decrypt(bytes(file_name, 'utf-8')).decode('utf-8')
    fout = os.path.join(out_folder, decrypted_name)

    with open(fin, 'rb') as fi, open(fout, 'wb') as fo:
        while True:
            size_data = fi.read(4)
            if len(size_data) == 0:
                break
            chunk = fi.read(struct.unpack('<I', size_data)[0])
            dec = fernet.decrypt(chunk)
            fo.write(dec)

def get_key() -> Fernet:
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
    return Fernet(key)

def main(encrypt_mode:str, input_folder: str, output_folder: str):
    fernet = get_key()

    if encrypt_mode not in ["ENCRYPT", "DECRYPT"]:
        print(f"Unknown mode: {encrypt_mode}")
        sys.exit(0)

    files = os.listdir(input_folder)
    total_file_size_bytes = 0
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for target_file_name in files:
            if encrypt_mode == "ENCRYPT":
                futures.append(executor.submit(encrypt_streaming, input_folder, output_folder, target_file_name, fernet))
            elif encrypt_mode == "DECRYPT":
                futures.append(executor.submit(decrypt_streaming, input_folder, output_folder, target_file_name, fernet))
            total_file_size_bytes += os.path.getsize(os.path.join(input_folder, target_file_name))
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res is not None:
                    print(res)
            except requests.ConnectTimeout:
                print("ConnectTimeout.")
            except InvalidToken:
                print("Invalid Key")


    execution_time = (time.time() - start_time)
    total_file_size_mb = total_file_size_bytes / (1024**2)
    mbps = total_file_size_mb / execution_time
    print(f'Execution time: {str(execution_time)}s\nProcessing speed: {mbps} MB/s')


if __name__ == "__main__":
    mode = "ENCRYPT"
    input_folder = "data"
    output_folder = "output"

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--decrypt", action='store_true', help="Sets mode to decryption")
    group.add_argument("-e", "--encrypt", action='store_true', help="Sets mode to encryption")

    parser.add_argument("-i","-in", "--input", default=None, type=str, help=f"defines folder to read from, default based on mode, one of: ['{input_folder}','encrypted']")
    parser.add_argument("-o","-out", "--output", default=None, type=str, help=f"defines folder to write to, default based on mode, one of: ['encrypted','decrypted'], will be created if not exist")


    args = parser.parse_args()

    if args.decrypt:
        mode = "DECRYPT"
        if args.input == None:
            input_folder = "encrypted"
        if args.output == None:
            output_folder = "decrypted"
    elif not args.decrypt: 
        if args.input == None:
            input_folder = "data"
        if args.output is None:
            output_folder = "encrypted"
    
    if args.output is not None:
        output_folder = args.output
    if args.input is not None:
        input_folder = args.input

    if not os.path.exists(input_folder):
        print(f"Input folder not found: {input_folder}")
        sys.exit(0)
    if not os.path.exists(output_folder):
        os.mkdir(output_folder)

    print(f"From {input_folder} {mode.lower()}ion to {output_folder}")
    main(mode, input_folder, output_folder)
