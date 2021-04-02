import argparse
import os
import sys
import json
from typing import Tuple
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

storage_name = 'storage.bin'


def create_parser():
    parser = argparse.ArgumentParser(description='Password Manager')

    arg_group = parser.add_mutually_exclusive_group(required=True)

    arg_group.add_argument('-init', metavar='master_password', nargs=1)
    arg_group.add_argument(
        '-put', metavar=('master_password', 'address', 'password'), nargs=3)
    arg_group.add_argument(
        '-get', metavar=('master_password', 'address'), nargs=2)

    return parser


def encrypt_storage(master_password: str, data: json):
    with open(storage_name, 'wb+') as f:
        salt = get_random_bytes(32)
        key = scrypt(master_password, salt, key_len=32, N=2**17, r=8, p=1)
        f.write(salt)

        cipher = AES.new(key, AES.MODE_GCM)
        f.write(cipher.nonce)

        encrypted_data = cipher.encrypt(data)
        f.write(encrypted_data)

        tag = cipher.digest()
        f.write(tag)


def decrypt_storage(master_password: str):
    with open(storage_name, 'rb+') as f:
        salt = f.read(32)
        key = scrypt(master_password, salt, key_len=32, N=2**17, r=8, p=1)

        nonce = f.read(16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        encrypted_data_size = os.path.getsize(storage_name) - 32 - 16 - 16
        encrypted_data = f.read(encrypted_data_size)
        decrypted_data = cipher.decrypt(encrypted_data)

        tag = f.read(16)

        try:
            cipher.verify(tag)
        except ValueError as e:
            print(
                'Storage file modified or incorrect password.\nReset with -init', file=sys.stderr)
            exit(1)

        return json.loads(decrypted_data.decode())


def init(master_password: str):
    master_password = master_password[0]
    encrypt_storage(master_password, '{}'.encode())
    print('Password manager initalized.')


def put(values: Tuple):
    master_password, address, password = values
    decrypted_storage: json = decrypt_storage(master_password)
    decrypted_storage.update({address: password})
    encrypt_storage(master_password, json.dumps(decrypted_storage).encode())
    print(f'Stored password for: {address}')


def get(values: Tuple):
    master_password, address = values
    decrypted_storage: json = decrypt_storage(master_password)
    if (password := decrypted_storage.get(address)) is not None:
        print(f'Password for {address} is: {password}')
    else:
        print('Specified address does not exist.')


if __name__ == '__main__':

    parser = create_parser()
    args = parser.parse_args()

    mode_dict = {'init': init,
                 'put': put,
                 'get': get}

    mode, values = [(arg, getattr(args, arg))
                    for arg in vars(args) if getattr(args, arg) is not None][0]

    if mode != 'init' and not os.path.isfile(storage_name):
        print('Password manager must be initalized first.\nUse -init to initalize.', file=sys.stderr)
        sys.exit(1)

    mode_dict[mode](values)
