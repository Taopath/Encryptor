import os
import sys
import struct
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def terminate_with_message(msg):
    os.system('clear')
    print(f'Error: {msg}')
    sys.exit()

def check_file_exists(file_path):
    if os.path.exists(file_path):
        return
    else:
        os.system('clear')
        terminate_with_message('file does not exist, terminating.')
        sys.exit()

import os
import struct
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def encrypt_file(input_file, output_file, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    # Compute SHA-256 hash of the plaintext
    hash_obj = SHA256.new(data)
    hash_digest = hash_obj.digest()
    data_with_hash = hash_digest + data

    # Padding data to be multiple of AES block size
    padding_length = 16 - len(data_with_hash) % 16
    data_with_hash += bytes([padding_length]) * padding_length

    ciphertext = cipher.encrypt(data_with_hash)

    with open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(iv)
        f_out.write(ciphertext)

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f_in:
        salt = f_in.read(16)
        iv = f_in.read(16)
        ciphertext = f_in.read()

    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    data_with_hash = cipher.decrypt(ciphertext)

    # Remove padding
    padding_length = data_with_hash[-1]
    data_with_hash = data_with_hash[:-padding_length]

    # Separate the hash from the decrypted data
    original_hash = data_with_hash[:32]
    data = data_with_hash[32:]

    # Compute hash of the decrypted data
    hash_obj = SHA256.new(data)
    new_hash = hash_obj.digest()

    # Verify the integrity of the decrypted data
    if original_hash != new_hash:
        terminate_with_message('invalid password or corrupted data.')

    with open(output_file, 'wb') as f_out:
        f_out.write(data)

def query_enc_file():
    os.system('clear')
    file_in = input('Enter file to encrypt:\n')
    check_file_exists(file_in)

    password = getpass.getpass('Enter encryption password:')
    file_name, ext = os.path.splitext(file_in)

    file_out = f'{file_name}.enc'

    encrypt_file(file_in, file_out, password)

    print(f'Done \nFile has been successfully encrypted as {file_out}')
    os.system('exit')

def query_dec_file():
    os.system('clear')
    file_in = input('Enter file to decrypt:\n')
    check_file_exists(file_in)

    password = getpass.getpass('Enter decryption password:')
    file_out = input('Enter output file name:\n')

    decrypt_file(file_in, file_out, password)

    print('Done \nFile has been successfully decrypted')
    os.system('exit')

def check_execution_parameters():
    if len(sys.argv) > 1:
        if sys.argv[1] == '-ef':
            query_enc_file()
            return True
        elif sys.argv[1] == '-df':
            query_dec_file()
            return True
        else:
            return False
    else:
        return False

def get_command_procedure():
    command = input('What would you like to do? Enter \"e" to encrypt or \"d" to decrypt:\n')
    if command == 'e':
        query_enc_file()
    elif command == 'd':
        query_dec_file()
    else:
        get_command_procedure()


def main():
    os.system('clear')
    if check_execution_parameters() == False:
        get_command_procedure()

if __name__ == '__main__':
    main()
