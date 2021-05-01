import sys
import re
import json
from getpass import getpass
from json.decoder import JSONDecodeError
from hashlib import scrypt

password_check_regex = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)


def login(username: str):
    password = getpass()
    with open("storage.json", "r+", encoding="utf-8") as f:
        try:
            storage: dict = json.load(f)
        except JSONDecodeError:
            print("Username or password incorrect.", file=sys.stderr)
            exit(1)
        if username not in storage or storage[username][0] != password:
            print("Username or password incorrect.", file=sys.stderr)
            exit(1)
        if storage[username][1]:
            new_password = getpass(prompt="New password: ")
            new_password_repeated = getpass(prompt="Repeat new password: ")

            if new_password != new_password_repeated:
                print("Password update failed. Password mismatch.", file=sys.stderr)
                exit(1)

            if password == new_password:
                print(
                    "New password must be different from the old one.", file=sys.stderr
                )
                exit(1)

            if not password_check_regex.match(new_password):
                print(
                    "Password must contain a minimum of eight characters, "
                    "at least one uppercase letter, "
                    "one lowercase letter, "
                    "one number and one special character.",
                    file=sys.stderr,
                )
                exit(1)

            storage.update({username: (new_password, False)})
            f.seek(0)
            f.truncate()
            json.dump(storage, f)

    print("Login successful.")


def main():
    if len(sys.argv) > 2:
        print(
            f"Invalid number of arguments.\nUsage: python {sys.argv[0]} [username]",
            file=sys.stderr,
        )
        exit(1)
    login(sys.argv[1])


if __name__ == "__main__":
    main()
