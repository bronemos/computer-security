import argparse
import sys
import json
import re
import secrets
from getpass import getpass
from json.decoder import JSONDecodeError
from hashlib import scrypt

password_check_regex = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="User Manager")

    arg_group = parser.add_mutually_exclusive_group(required=True)
    arg_group.add_argument("-add")
    arg_group.add_argument("-passwd")
    arg_group.add_argument("-forcepass")
    arg_group.add_argument("-del")

    return parser


def add(username: str):
    with open("storage.json", "w+", encoding="utf-8") as f:
        try:
            storage: dict = json.load(f)
            if username in storage:
                print("User add failed. User already exists.", file=sys.stderr)
                exit(1)
        except JSONDecodeError:
            pass

    password = getpass()
    password_repeated = getpass(prompt="Repeat Password: ")

    if password != password_repeated:
        print("User add failed. Password mismatch.", file=sys.stderr)
        exit(1)

    if not password_check_regex.match(password):
        print(
            "Password must contain a minimum of eight characters, "
            "at least one uppercase letter, "
            "one lowercase letter, "
            "one number and one special character.",
            file=sys.stderr,
        )
        exit(1)

    with open("storage.json", "r+", encoding="utf-8") as f:
        try:
            storage: dict = json.load(f)
        except JSONDecodeError:
            storage = dict()

        storage.update(
            {
                username: (
                    scrypt(
                        password=password.encode(encoding="utf-8"),
                        salt=(salt := secrets.token_bytes(32)),
                        n=16384,
                        r=8,
                        p=1,
                        dklen=32,
                    ).hex(),
                    False,
                    salt.hex(),
                )
            }
        )
        f.seek(0)
        f.truncate()
        json.dump(storage, f)

    print("User add successfuly added.")


def passwd(username: str):
    password = getpass()
    password_repeated = getpass(prompt="Repeat password: ")

    if password != password_repeated:
        print("Password change failed. Password mismatch.", file=sys.stderr)
        exit(1)

    if not password_check_regex.match(password):
        print(
            "Password must contain a minimum of eight characters, "
            "at least one uppercase letter, "
            "one lowercase letter, "
            "one number and one special character.",
            file=sys.stderr,
        )
        exit(1)

    with open("storage.json", "r+", encoding="utf-8") as f:
        try:
            storage: dict = json.load(f)
        except JSONDecodeError:
            print(
                "Password change failed. Requested user does not exist.",
                file=sys.stderr,
            )
            exit(1)
        if username not in storage:
            print(
                "Password change failed. Requested user does not exist.",
                file=sys.stderr,
            )
            exit(1)
        storage.update(
            {
                username: (
                    scrypt(
                        password=password.encode(encoding="utf-8"),
                        salt=(salt := secrets.token_bytes(32)),
                        n=16384,
                        r=8,
                        p=1,
                        dklen=32,
                    ).hex(),
                    storage[username][1],
                    salt.hex(),
                )
            }
        )
        f.seek(0)
        f.truncate()
        json.dump(storage, f)

    print("Password change successful.")


def forcepass(username: str):
    with open("storage.json", "r+", encoding="utf-8") as f:
        try:
            storage: dict = json.load(f)
        except JSONDecodeError:
            print(
                "Force password change failed. Requested user does not exist.",
                file=sys.stderr,
            )
            exit(1)
        if username not in storage:
            print(
                "Force password change failed. Requested user does not exist.",
                file=sys.stderr,
            )
            exit(1)
        storage.update({username: (storage[username][0], True, storage[username][2])})
        f.seek(0)
        f.truncate()
        json.dump(storage, f)

    print("User will be requested to change password on next login.")


def del_(username: str):
    with open("storage.json", "r+", encoding="utf-8") as f:
        try:
            storage: dict = json.load(f)
        except JSONDecodeError:
            print("User delete failed. Requested user does not exist.", file=sys.stderr)
            exit(1)
        if username not in storage:
            print("User delete failed. Requested user does not exist.", file=sys.stderr)
            exit(1)
        storage.pop(username)
        f.seek(0)
        f.truncate()
        json.dump(storage, f)

    print("User successfuly removed.")


def main():
    instruction_dict = {
        "add": add,
        "passwd": passwd,
        "forcepass": forcepass,
        "del": del_,
    }
    parser = create_parser()
    args = parser.parse_args()
    instruction, username = [
        (instruction, getattr(args, instruction))
        for instruction in vars(args)
        if getattr(args, instruction) is not None
    ][0]
    instruction_dict[instruction](username)


if __name__ == "__main__":
    main()
