from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import getpass
import re

password = ""

def draw_logo():
    logo = """
    =====================================
       E  N  V  Y  S  T   (Secure Vault)
    =====================================
    """
    print(logo)

def show_menu():
    menu = """
    ------------------------------
    Select an option:
    1. Setup Password
    2. List Account
    3. List Wallet (Seed)
    4. List Wallet (Private Key)
    5. List Wallet (Other)
    6. Add
    7. Delete
    8. Exit
    ------------------------------
    """
    print(menu)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + ciphertext).decode()

def decrypt_data(token, password):
    decoded_data = urlsafe_b64decode(token)
    salt, iv, ciphertext = decoded_data[:16], decoded_data[16:32], decoded_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        return None

def file_name_encrypt(data, password):
    encrypted = encrypt_data(data, password)
    return encrypted.replace("/", "_").replace("+", "-")

def file_name_decrypt(token, password):
    token = token.replace("_", "/").replace("-", "+")
    decrypted = decrypt_data(token, password)
    return decrypted.decode() if decrypted else None

def setup_password():
    global password
    password = getpass.getpass("Enter a new password: ")
    print("Password set successfully.")

def validate_seed(seed):
    words = seed.split()
    return len(words) in [12, 24]

def validate_private_key(private_key):
    return private_key.startswith("0x") and len(private_key) == 66

def save_to_file(directory, file_name, content):
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(os.path.join(directory, file_name), "w") as file:
        file.write(content)

def account_name_exists(directory, account_name):
    if not os.path.exists(directory):
        return False

    for file_name in os.listdir(directory):
        decrypted_name = file_name_decrypt(file_name, password)
        if decrypted_name == account_name:
            return True

    return False

def list_and_choose(directory):
    global password
    if not password:
        print("Please set up a password first.")
        return
    if not os.path.exists(directory):
        print("No data available.")
        return None

    files = os.listdir(directory)
    if not files:
        print("No data available.")
        return None

    print("Available entries:")
    decrypted_files = []
    for idx, file_name in enumerate(files, start=1):
        decrypted_name = file_name_decrypt(file_name, password)
        if decrypted_name:
            decrypted_files.append((idx, decrypted_name, file_name))
            print(f"{idx}. {decrypted_name}")

    choice = input("Choose an entry by number: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(decrypted_files):
        print("Invalid choice.")
        return None

    selected = decrypted_files[int(choice) - 1]
    with open(os.path.join(directory, selected[2]), "r") as file:
        content = file.read()

    decrypted_content = decrypt_data(content, password)

    # Decode the byte string into a regular string
    decoded_data = decrypted_content.decode('utf-8')

    # Print the formatted output
    print("Details:")
    print("------------------------------------")
    for line in decoded_data.split('\n'):
        print(line.strip())
    print("------------------------------------")
    
    return selected[1]

def delete_data():
    global password
    if not password:
        print("Please set up a password first.")
        return
    opts = """
    1. Account
    2. Wallet (Seed)
    3. Wallet (Private Key)
    4. Other
    """
    print(opts)
    choice = input("Choose Account Type: ").strip()

    if choice == "1":
        list_and_delete("accounts")
    elif choice == "2":
        list_and_delete("seeds")
    elif choice == "3":
        list_and_delete("private_keys")
    elif choice == "4":
        list_and_delete("others")
    else:
        print("Invalid option")
    
def list_and_delete(directory):
    if not os.path.exists(directory):
        print("No data available.")
        return None

    files = os.listdir(directory)
    if not files:
        print("No data available.")
        return None

    print("Available entries:")
    decrypted_files = []
    for idx, file_name in enumerate(files, start=1):
        decrypted_name = file_name_decrypt(file_name, password)
        if decrypted_name:
            decrypted_files.append((idx, decrypted_name, file_name))
            print(f"{idx}. {decrypted_name}")

    choice = input("Choose to delete by number: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(decrypted_files):
        print("Invalid choice.")
        return None

    sure = input("Are you sure? (y/n) ").strip()
    if sure.lower() == "y":
        selected = decrypted_files[int(choice) - 1]
        
        selected_file_path = os.path.join(directory, selected[2])
        selected_file_name = file_name_decrypt(selected[2], password)
        # Check if the file exists
        if os.path.exists(selected_file_path):
            os.remove(selected_file_path)
            print(f" '{selected_file_name}' has been deleted.")
        else:
            print(f" '{selected_file_name}' does not exist.")
        return selected[1]

def add_data():
    global password
    if not password:
        print("Please set up a password first.")
        return

    print("Choose data type to add:")
    print("1. Account\n2. Seed\n3. Private Key\n4. Other")
    choice = input("Enter your choice: ").strip()

    if choice == "1":
        directory = "accounts"
        while True:
            account_name = input("Enter Account Name: ").strip()
            if account_name_exists(directory, account_name):
                print("Account Name already exists. Please use another name.")
            else:
                break

        username = input("Enter Username: ").strip()
        acc_password = input("Enter Password: ").strip()
        other_data = input("Enter Other Data (key=value, separate by commas): ").strip()

        content = f"Account Name = {account_name}\nUsername = {username}\nPassword = {acc_password}"
        if other_data:
            for pair in other_data.split(","):
                key, value = pair.split("=", 1)
                content += f"\n{key.strip()} = {value.strip()}"
                
        encrypted_content = encrypt_data(content, password)

        file_name = file_name_encrypt(account_name, password)
        save_to_file(directory, file_name, encrypted_content)
        print("Account added successfully.")

    elif choice == "2":
        directory = "seeds"
        while True:
            wallet_name = input("Enter Wallet Name: ").strip()
            if account_name_exists(directory, wallet_name):
                print("Wallet Name already exists. Please use another name.")
            else:
                break
        seed = input("Enter Seed (12 or 24 words): ").strip()

        if not validate_seed(seed):
            print("Invalid seed. Must be 12 or 24 words.")
            return

        content = f"Wallet Name = {wallet_name}\nSeed = {seed}"
        
        encrypted_content = encrypt_data(content, password)
        file_name = file_name_encrypt(wallet_name, password)
        save_to_file(directory, file_name, encrypted_content)
        print("Seed added successfully.")

    elif choice == "3":
        directory = "private_keys"
        while True:
            wallet_name = input("Enter Wallet Name: ").strip()
            if account_name_exists(directory, wallet_name):
                print("Wallet Name already exists. Please use another name.")
            else:
                break
        private_key = input("Enter Private Key: ").strip()

        if not validate_private_key(private_key):
            print("Invalid private key. Must start with 0x and be 66 characters long.")
            return

        content = f"Wallet Name = {wallet_name}\nPrivate Key = {private_key}"
        
        encrypted_content = encrypt_data(content, password)
        file_name = file_name_encrypt(wallet_name, password)
        save_to_file(directory, file_name, encrypted_content)
        print("Private key added successfully.")

    elif choice == "4":
        directory = "others"
        while True:
            type_name = input("Enter Type Name: ").strip()
            if account_name_exists(directory, type_name):
                print("Type Name already exists. Please use another name.")
            else:
                break
        other_data = input("Enter Other Data (key=value, separate by commas): ").strip()

        content = f"Type Name = {type_name}"
        if other_data:
            for pair in other_data.split(","):
                key, value = pair.split("=", 1)
                content += f"\n{key.strip()} = {value.strip()}"
        
        encrypted_content = encrypt_data(content, password)
        file_name = file_name_encrypt(type_name, password)
        save_to_file(directory, file_name, encrypted_content)
        print("Other data added successfully.")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    draw_logo()
    while True:
        show_menu()
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            setup_password()
        elif choice == "2":
            list_and_choose("accounts")
        elif choice == "3":
            list_and_choose("seeds")
        elif choice == "4":
            list_and_choose("private_keys")
        elif choice == "5":
            list_and_choose("others")
        elif choice == "6":
            add_data()
        elif choice == "7":
            delete_data()
        elif choice == "8":
            print("Exiting... Goodbye!")
            break
        elif choice.lower() == "exit":
            print("Exiting... Goodbye!")
            break
        else:
            print("Invalid option. Try again.")
