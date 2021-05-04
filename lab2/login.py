import sys
import re
import json
import os
from getpass import getpass
from json.decoder import JSONDecodeError
from hashlib import scrypt
from time import sleep
import secrets

password_check_regex = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)

timeout = 10
timeout_multiplier = 2
max_attempt_count = 3


def login(username: str):
    global timeout
    attempt_counter = 0

    while True:
        if attempt_counter == max_attempt_count:
            attempt_counter = 0
            for i in range(timeout, -1, -1):
                print(
                    "\x1b[2K\r"
                    + f"Too many failed attempts. Please wait {i} seconds before trying again.",
                    end="\r",
                )
                sleep(1)
            timeout *= timeout_multiplier
            print("\x1b[2K\r", end="\r")
        password = getpass()
        with open("storage.json", "r+", encoding="utf-8") as f:
            try:
                storage: dict = json.load(f)
            except JSONDecodeError:
                attempt_counter += 1
                print(
                    f"Username or password incorrect. {max_attempt_count - attempt_counter} attempts remaining.",
                    file=sys.stderr,
                )
                continue

            if (
                username not in storage
                or storage[username][0]
                != scrypt(
                    password=password.encode("utf-8"),
                    salt=bytes.fromhex(storage[username][2]),
                    n=16384,
                    r=8,
                    p=1,
                    dklen=32,
                ).hex()
            ):
                attempt_counter += 1
                print(
                    f"Username or password incorrect. {max_attempt_count - attempt_counter} attempts remaining.",
                    file=sys.stderr,
                )
                continue

            if storage[username][1]:
                while True:
                    new_password = getpass(prompt="New password: ")
                    new_password_repeated = getpass(prompt="Repeat new password: ")

                    if new_password != new_password_repeated:
                        print(
                            "Password update failed. Password mismatch.",
                            file=sys.stderr,
                        )
                        continue

                    if password == new_password:
                        print(
                            "New password must be different from the old one.",
                            file=sys.stderr,
                        )
                        continue

                    if not password_check_regex.match(new_password):
                        print(
                            "Password must contain a minimum of eight characters, "
                            "at least one uppercase letter, "
                            "one lowercase letter, "
                            "one number and one special character.",
                            file=sys.stderr,
                        )
                        continue

                    storage.update(
                        {
                            username: (
                                scrypt(
                                    password=new_password.encode(encoding="utf-8"),
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
                    break
            break

    print("Login successful.")


def main():
    if not os.path.isfile("storage.json"):
        with open("storage.json", "w+") as f:
            pass

    if len(sys.argv) > 2:
        print(
            f"Invalid number of arguments.\nUsage: python {sys.argv[0]} [username]",
            file=sys.stderr,
        )
        exit(1)

    login(sys.argv[1])


if __name__ == "__main__":
    main()
