# ENVYST Secure Vault

ENVYST Secure Vault is a Python-based application designed to securely store all your credentials locally in one app. By leveraging encryption techniques, it ensures that your sensitive information remains protected on your local machine.

## Features

- **Local Storage**: All credentials are stored locally, giving you full control over your data.
- **Encryption**: Utilizes AES-256 encryption to safeguard your credentials.
- **User-Friendly Interface**: Simple command-line interface for easy interaction.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/envyst/ENVYST-secure-vault.git
   ```

2. **Navigate to the Project Directory**:

   ```bash
   cd ENVYST-secure-vault
   ```

3. **Create a Virtual Environment** (optional but recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

4. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the Application**:

   ```bash
   python envyst.py
   ```

2. **Follow the On-Screen Prompts**:

   - Add new credentials by providing a service name, username, and password.
   - Retrieve stored credentials by specifying the service name.
   - Delete credentials as needed.

## Security

ENVYST Secure Vault employs AES-256 encryption to ensure that your credentials are stored securely. The encryption key is derived from a master password that you set upon first use. It is crucial to remember this master password, as it is required to access your stored credentials.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to enhance the functionality of ENVYST Secure Vault.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

Special thanks to the open-source community for providing valuable resources and inspiration.

---

*Note: Always ensure that your local environment is secure and that you have backups of your credentials.*
