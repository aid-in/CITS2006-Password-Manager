import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

DATA_FILE = "vault.json"
SALT = b'\xa0\xac\x17U\xcc\xb8\xea#\xab\x14\x92\xe2\xc4\xd1y\xae'

def get_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def add_account(key, data):
    site = input("Enter site name: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    data[site] = {"username": username, "password": encrypted.decode()}
    save_data(data)
    print("Account saved.")

def retrieve_account(key, data):
    site = input("Enter site name: ")
    if site in data:
        f = Fernet(key)
        decrypted = f.decrypt(data[site]["password"].encode()).decode()
        print(f"Username: {data[site]['username']}\nPassword: {decrypted}")
    else:
        print("No such account.")

def list_accounts(data):
    for site in data:
        print(f"- {site}")

def main():
    password = getpass.getpass("Enter master password: ")
    key = get_key(password)
    data = load_data()

    while True:
        print("\n1. Add Account\n2. Retrieve Account\n3. List Accounts\n4. Exit")
        choice = input("Choice: ")
        if choice == "1":
            add_account(key, data)
        elif choice == "2":
            retrieve_account(key, data)
        elif choice == "3":
            list_accounts(data)
        elif choice == "4":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
