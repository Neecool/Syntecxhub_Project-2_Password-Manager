#  Password Manager 
## Internship Project 2 for Syntecxhub 
A secure, local password manager built in Python using AES-GCM encryption. 
Store, retrieve, and manage your passwords safely with a master password.

**Tech Stack:** Python, `cryptography` (AES-GCM, PBKDF2-HMAC)

---

##  Introduction
Developed as part of my internship at **Syntecxhub (Project 2)**, this project is a fully functional local password manager. 
It demonstrates applied cryptography, secure key derivation, and safe storage of sensitive data. All your credentials are encrypted on disk and protected by a single master password.

---

##  Features
-  **AES-GCM Encryption**: Industry-standard symmetric encryption with authentication.
-  **Secure Key Derivation**: Uses PBKDF2-HMAC with a random salt (100,000 iterations) to prevent brute-force attacks.
-  **Encrypted JSON Storage**: All data is stored in a single binary file (`vault.enc`).
-  **Add Entry**: Store service, username, and password.
-  **Retrieve Entry**: Fetch credentials by service name.
-  **Delete Entry**: Remove unwanted credentials.
-  **List All**: View all stored services.
-  **Search**: Find entries by service name or username.

---

##  Technologies Used
- **Python 3.x**
- **Cryptography Library**:
  - `AESGCM` (Encryption)
  - `PBKDF2HMAC` (Key Derivation)
  - `SHA256` (Hashing)

---

##  How to Run the Project?

###  Prerequisites:
- Python 3.6+
- Install the cryptography library:
```bash
pip install cryptography

```
## Setup & Execution
1.Clone the repository (replace your‑username with your actual GitHub username):

```bash
git clone https://github.com/your-username/Password-Manager.git
cd Password-Manager
```
2. Run the manager:

```bash
python password_manager.py
```
3. First‑time setup:

You will be prompted to create a Master Password (minimum 4 characters).
⚠️ Remember this password! It is the only key to decrypt your vault.

4. Using the Menu:

Choose options 1‑6 from the interactive menu.
Your data is automatically saved and encrypted after every change.

