from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import getpass
import re
#---------------- Sect2
import webbrowser
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
import io
import platform
#---------------- Sect2

password = ""

def draw_logo():
    logo = """
    =====================================
       E  N  V  Y  S  T   (Secure Vault)
    =====================================
    """
    print(logo)

def show_menu():
    clear_screen()
    draw_logo()
    menu = """
    Select an option:
    1. Setup Password
    2. List Account
    3. List Wallet (Seed)
    4. List Wallet (Private Key)
    5. List Wallet (Other)
    6. Add
    7. Delete
    8. Setup Google Credentials
    9. Sync Google Drive
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
        rust = input("Press Any Key to Return to Menu")
        return
    if not os.path.exists(directory):
        print("No data available.")
        rust = input("Press Any Key to Return to Menu")
        return None

    files = os.listdir(directory)
    if not files:
        print("No data available.")
        rust = input("Press Any Key to Return to Menu")
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
    rust = input("Press Any Key to Return to Menu")
    
    return selected[1]

def delete_data():
    global password
    if not password:
        print("Please set up a password first.")
        rust = input("Press Any Key to Return to Menu")
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
            drive_file_path = f"{directory}/{selected[2]}"
            delete_file_from_drive(drive_file_path)
            print(f" '{selected_file_name}' has been deleted.")
            rust = input("Press Any Key to Return to Menu")
        else:
            print(f" '{selected_file_name}' does not exist.")
            rust = input("Press Any Key to Return to Menu")
        return selected[1]

def add_data():
    global password
    if not password:
        print("Please set up a password first.")
        rust = input("Press Any Key to Return to Menu")
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
        

#---------------- Sect2
def clear_screen():
    # Check the platform and clear the screen
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def setup_google_credentials():
    print("Step 1: Go to the Google Cloud Console.")
    webbrowser.open("https://console.cloud.google.com/")

    print("\nStep 2: Create or select a project.")
    print("- If you don't have a project, click 'New Project'.")
    print("- Provide a project name and click 'Create'.")
    input("Press Enter after creating/selecting a project to continue...")

    print("\nStep 3: Enable the Google Drive API.")
    webbrowser.open("https://console.cloud.google.com/apis/library/drive.googleapis.com")
    print("- Click 'Enable' to activate the API for your project.")
    input("Press Enter after enabling the API to continue...")

    print("\nStep 4: Configure the OAuth consent screen.")
    webbrowser.open("https://console.cloud.google.com/apis/credentials/consent")
    print("- Choose 'External' for the user type if needed.")
    print("- Fill in the required details (e.g., app name, email).")
    print("- Add Test User Using your email.")
    print("- Save the configuration.")
    input("Press Enter after configuring the OAuth consent screen to continue...")

    print("\nStep 5: Create OAuth 2.0 Credentials.")
    webbrowser.open("https://console.cloud.google.com/apis/credentials")
    print("- Click 'Create Credentials' > 'OAuth Client ID'.")
    print("- Select 'Desktop App' as the application type.")
    print("- Provide a name and click 'Create'.")
    print("- Download the 'credentials.json' file.")
    print("- Open the 'credentials.json' file, copy all its content.")
    print("- Return to this terminal and paste the content when prompted.")
    
    # Prompt user to paste the content of credentials.json
    credentials_content = input("\nPaste the content of 'credentials.json' here:\n")
    
    try:
        # Validate JSON content
        json_data = json.loads(credentials_content)
        
        # Write content to a credentials.json file
        with open("credentials.json", "w") as credentials_file:
            json.dump(json_data, credentials_file, indent=4)
        print("\nThe 'credentials.json' file has been saved successfully!")
    except json.JSONDecodeError:
        print("\nInvalid JSON content. Please ensure you copied the content correctly.")

    print("\nSetup Complete!")
    print("You should now have 'credentials.json' in your project directory.")
    print("You can run your Python script to authenticate and use the Google Drive API.")
   
# Define the scope
SCOPES = ['https://www.googleapis.com/auth/drive']

def authenticate():
    """Authenticate the user and return the Google Drive service."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    service = build('drive', 'v3', credentials=creds)
    return service

def get_drive_folder_id(service, folder_name, parent_id=None):
    """Get or create a folder on Google Drive and return its ID."""
    query = f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder'"
    if parent_id:
        query += f" and '{parent_id}' in parents"
    results = service.files().list(q=query, fields="files(id, name)").execute()
    items = results.get('files', [])
    if items:
        return items[0]['id']
    else:
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id] if parent_id else []
        }
        folder = service.files().create(body=file_metadata, fields='id').execute()
        return folder['id']

def upload_file(service, file_path, drive_folder_id):
    """Upload a file to Google Drive."""
    file_name = os.path.basename(file_path)
    file_metadata = {'name': file_name, 'parents': [drive_folder_id]}
    media = MediaFileUpload(file_path, resumable=True)
    service.files().create(body=file_metadata, media_body=media, fields='id').execute()

def download_file(service, file_id, local_path):
    """Download a file from Google Drive."""
    request = service.files().get_media(fileId=file_id)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    with io.FileIO(local_path, 'wb') as file:
        downloader = MediaIoBaseDownload(file, request)
        done = False
        while not done:
            _, done = downloader.next_chunk()

def list_drive_files(service, folder_id):
    """List files in a Google Drive folder."""
    query = f"'{folder_id}' in parents"
    results = service.files().list(q=query, fields="files(id, name, mimeType)").execute()
    return results.get('files', [])

def delete_file_from_drive(file_path):
    """
    Delete a file from Google Drive based on its path.
    
    Args:
        service: The authenticated Google Drive API service instance.
        drive_path: The path to the file on Google Drive.
    """
    try:
        with open("credentials.json", "r") as file:
            content = file.read()
            is_valid, message = validate_credentials(content)
            if is_valid:
                print("Validation successful:", message)
                service = authenticate()
                # Search for the file on Google Drive by its path
                drive_base_dir = "ENVYST-Secure-Vault"
                drive_path = f"{drive_base_dir}/{file_path}"
                query = f"name = '{drive_path.split('/')[-1]}' and trashed = false"
                results = service.files().list(
                    q=query,
                    spaces='drive',
                    fields="files(id, name)"
                ).execute()
                items = results.get('files', [])

                if not items:
                    print(f"File '{drive_path}' not found on Google Drive.")
                else:
                    # Delete all matching files (ideally only one)
                    for item in items:
                        file_id = item['id']
                        service.files().delete(fileId=file_id).execute()
                        print(f"Deleted '{item['name']}' from Google Drive.")
            else:
                print("Validation failed:", message)
    except FileNotFoundError:
        print("Error: credentials.json file not found.")
        print("Please Setup Credentials first!!!.")
    except Exception as e:
        print(f"Error deleting file '{drive_path}' from Google Drive: {e}")

def sync_account():
    """Synchronize files between local directories and Google Drive."""
    try:
        with open("credentials.json", "r") as file:
            content = file.read()
            is_valid, message = validate_credentials(content)
            if is_valid:
                print("Validation successful:", message)
                service = authenticate()

                # Define root folders
                local_root = os.getcwd()
                drive_root_name = 'ENVYST-Secure-Vault'
                drive_root_id = get_drive_folder_id(service, drive_root_name)

                # Define subdirectories to sync
                subdirs = ['accounts', 'seeds', 'private_keys', 'others']

                for subdir in subdirs:
                    local_subdir = os.path.join(local_root, subdir)
                    drive_subdir_id = get_drive_folder_id(service, subdir, parent_id=drive_root_id)

                    # Ensure local subdirectory exists
                    os.makedirs(local_subdir, exist_ok=True)

                    # List local files
                    local_files = {file: os.path.join(local_subdir, file) for file in os.listdir(local_subdir)}

                    # List Drive files
                    drive_files = {file['name']: file['id'] for file in list_drive_files(service, drive_subdir_id)}

                    # Upload missing files to Drive
                    for local_file, local_path in local_files.items():
                        if local_file not in drive_files:
                            print(f"Uploading {local_file} to Drive...")
                            upload_file(service, local_path, drive_subdir_id)

                    # Download missing files from Drive
                    for drive_file, drive_id in drive_files.items():
                        if drive_file not in local_files:
                            print(f"Downloading {drive_file} from Drive...")
                            download_file(service, drive_id, os.path.join(local_subdir, drive_file))

            else:
                print("Validation failed:", message)
    except FileNotFoundError:
        print("Error: credentials.json file not found.")
        print("Please Setup Credentials first!!!.")
    
def validate_credentials(content):
    """
    Validate the content of the Google OAuth credentials.json file.

    Args:
        content (str): The JSON content as a string.

    Returns:
        bool: True if valid, False otherwise.
        str: Error message if invalid, or "Valid" if valid.
    """
    try:
        # Parse the JSON content
        data = json.loads(content)
        
        # Check if the structure contains "installed" or "web"
        if "installed" in data:
            client_data = data["installed"]
        elif "web" in data:
            client_data = data["web"]
        else:
            return False, "Missing 'installed' or 'web' root key in the JSON structure."
        
        # Validate essential keys in the client data
        required_keys = ["client_id", "project_id", "auth_uri", "token_uri", "client_secret", "redirect_uris"]
        for key in required_keys:
            if key not in client_data:
                return False, f"Missing key '{key}' in the JSON structure."
        
        # Ensure "redirect_uris" is a list and not empty
        if not isinstance(client_data["redirect_uris"], list) or not client_data["redirect_uris"]:
            return False, "Invalid or missing 'redirect_uris'. It should be a non-empty list."

        return True, "Valid credentials.json content."

    except json.JSONDecodeError:
        return False, "Invalid JSON format. Please check for syntax errors."

#---------------- Sect2

if __name__ == "__main__":
    while True:
        show_menu()
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            clear_screen()
            setup_password()
        elif choice == "2":
            clear_screen()
            list_and_choose("accounts")
        elif choice == "3":
            clear_screen()
            list_and_choose("seeds")
        elif choice == "4":
            clear_screen()
            list_and_choose("private_keys")
        elif choice == "5":
            clear_screen()
            list_and_choose("others")
        elif choice == "6":
            clear_screen()
            add_data()
        elif choice == "7":
            clear_screen()
            delete_data()
        elif choice == "8":
            clear_screen()
            setup_google_credentials()
        elif choice == "9":
            clear_screen()
            sync_account()
        elif choice.lower() == "exit":
            print("Exiting... Goodbye!")
            clear_screen()
            break
        else:
            print("Invalid option. Try again.")
