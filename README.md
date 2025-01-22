# ENVYST Secure Vault

ENVYST Secure Vault is a Python-based application that allows you to securely store and manage all your credentials locally in one place. By leveraging encryption, it ensures that your sensitive information remains protected on your device. Additionally, you can sync your credentials with your Google Drive account for backup and accessibility.

## Features

- **Local Storage**: Keep all your credentials stored locally, reducing the risk associated with cloud storage.
- **Encryption**: Protect your data with robust encryption methods.
- **Google Drive Sync**: Easily back up and restore your encrypted credentials using your Google Drive account.
- **User-Friendly Interface**: Interact with your credentials through a simple command-line interface.

## Installation

To get started with ENVYST Secure Vault, follow these steps:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/envyst/ENVYST-secure-vault.git
   ```

2. **Navigate to the Project Directory**:

   ```bash
   cd ENVYST-secure-vault
   ```

3. **Set Up a Virtual Environment**:

   It is recommended to use a virtual environment to manage dependencies. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install the Required Dependencies**:

   Ensure you have Python installed on your system. Then, install the necessary packages:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Running the Application**:

   Execute the `envyst.py` script to start the application:

   ```bash
   python envyst.py
   ```

   Alternatively, you can download the pre-built `envyst.exe` file from the `dist` directory in the repository. As long as Python is installed on your device, you can run the executable directly for ease of use.

2. **Storing a New Credential**:

   Follow the on-screen prompts to input and save a new credential. The application will encrypt and store it locally.

3. **Retrieving a Credential**:

   Use the application's interface to select and view your stored credentials. Decryption will occur in-memory to maintain security.

4. **Syncing with Google Drive**:

   - **Setup**: The first time you run the application, you will be prompted to authenticate your Google account.
   - **Backup**: Choose the option to sync your encrypted credentials with Google Drive.
   - **Restore**: Retrieve your encrypted backup from Google Drive to restore credentials on a new device or after reinstalling the application.

## Security Considerations

- **Encryption Key Management**: Ensure that your encryption key is stored securely and not hard-coded within the script.
- **Local Storage**: Regularly back up your encrypted credentials to prevent data loss.
- **Google Drive Authentication**: Do not share your Google account credentials or access tokens with anyone.
- **Dependencies**: Keep your dependencies up to date to mitigate potential security vulnerabilities.

## Contributing

We welcome contributions to enhance ENVYST Secure Vault. Feel free to fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

Special thanks to the contributors and the open-source community for their support.