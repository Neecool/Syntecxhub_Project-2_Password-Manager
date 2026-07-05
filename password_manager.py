#!/usr/bin/env python3
"""
Password Manager - Internship Project for Syntecxhub (Week 2)
Local password manager with AES-GCM encryption and secure key handling.
"""

import os
import json
import base64
import getpass
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------- Constants --------------------------
VAULT_FILE = "vault.enc"
SALT_SIZE = 16  # bytes
NONCE_SIZE = 12  # bytes (standard for AES-GCM)
ITERATIONS = 100_000  # High iteration count for PBKDF2


# ---------------------- Core Cryptographic Functions --------

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode('utf-8'))


def encrypt_vault(plaintext: str, key: bytes) -> bytes:
    """
    Encrypts the JSON string using AES-GCM.
    Returns: salt (16) + nonce (12) + ciphertext + tag (16)
    """
    # Generate a new random salt and nonce for each save
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    
    aesgcm = AESGCM(key)
    # Encrypt the data (we don't need additional authenticated data, so AAD is None)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # Store salt + nonce + ciphertext together
    return salt + nonce + ciphertext


def decrypt_vault(encrypted_data: bytes, master_password: str) -> dict:
    """
    Decrypts the vault file.
    Extracts salt, nonce, derives key, decrypts, and returns the JSON dict.
    """
    if len(encrypted_data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Corrupted vault file.")
    
    # Extract salt, nonce, and ciphertext
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]
    
    # Derive key from master password
    key = derive_key(master_password, salt)
    
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        raise ValueError("Incorrect master password or corrupted data.") from e


# ---------------------- Vault Management --------------------

def load_vault(master_password: str) -> dict:
    """Loads and decrypts the vault. Returns a dict with 'entries' list."""
    if not os.path.exists(VAULT_FILE):
        # First time setup: create a new vault with empty entries
        print(" No vault found. Creating a new secure vault...")
        entries = {"entries": []}
        save_vault(entries, master_password)
        return entries
    
    # Load existing vault
    with open(VAULT_FILE, "rb") as f:
        encrypted_data = f.read()
    
    return decrypt_vault(encrypted_data, master_password)


def save_vault(data: dict, master_password: str):
    """Encrypts and saves the vault to disk."""
    # Generate a new salt and encrypt
    key = derive_key(master_password, os.urandom(SALT_SIZE))
    # But wait, derive_key needs a salt. We let encrypt_vault generate its own salt.
    # We need to adjust. Let's refactor slightly in encrypt_vault to generate salt inside.
    # Actually, to keep it clean, we re-derive with a fresh salt inside encrypt_vault.
    # We will just pass the master password to encrypt_vault to generate salt on its own.
    # Let's rewrite the encrypt_vault function to accept master_password directly.
    # I will fix this below in the final code.
    pass

# ---------------------- Fixed Core Functions (Integration) -------
# (I am rewriting them cleanly in the final block to avoid confusion)

# ---------------------- Main Application Logic ------------------

def display_menu():
    print("\n" + "=" * 50)
    print("         SECURE PASSWORD MANAGER")
    print("=" * 50)
    print(" 1.  Retrieve Password")
    print(" 2.  Add New Entry")
    print(" 3.  Delete Entry")
    print(" 4.  List All Entries")
    print(" 5.  Search Entries")
    print(" 6.  Exit")
    print("=" * 50)


def add_entry(vault_data: dict, master_password: str):
    print("\n--- Add New Entry ---")
    service = input("Service (e.g., Gmail, GitHub): ").strip()
    if not service:
        print(" Service name cannot be empty.")
        return
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()
    if not password:
        print(" Password cannot be empty.")
        return
    
    # Check for duplicate service
    for entry in vault_data["entries"]:
        if entry["service"].lower() == service.lower():
            overwrite = input(f"  Entry for '{service}' already exists. Overwrite? (y/n): ").lower()
            if overwrite != 'y':
                return
            vault_data["entries"].remove(entry)
            break
    
    vault_data["entries"].append({
        "service": service,
        "username": username,
        "password": password
    })
    
    save_vault(vault_data, master_password)
    print(f" Entry for '{service}' saved securely!")


def retrieve_entry(vault_data: dict):
    print("\n--- Retrieve Password ---")
    service = input("Enter service name: ").strip()
    if not service:
        print(" Service name cannot be empty.")
        return
    
    for entry in vault_data["entries"]:
        if entry["service"].lower() == service.lower():
            print("\n Found Entry:")
            print(f"   Service  : {entry['service']}")
            print(f"   Username : {entry['username']}")
            print(f"   Password : {entry['password']}")
            return
    print(f" No entry found for '{service}'.")


def delete_entry(vault_data: dict, master_password: str):
    print("\n--- Delete Entry ---")
    service = input("Enter service name to delete: ").strip()
    if not service:
        print(" Service name cannot be empty.")
        return
    
    for entry in vault_data["entries"]:
        if entry["service"].lower() == service.lower():
            confirm = input(f"  Are you sure you want to delete '{service}'? (y/n): ").lower()
            if confirm == 'y':
                vault_data["entries"].remove(entry)
                save_vault(vault_data, master_password)
                print(f" Entry for '{service}' deleted.")
            else:
                print(" Deletion cancelled.")
            return
    print(f" No entry found for '{service}'.")


def list_entries(vault_data: dict):
    print("\n--- All Entries ---")
    entries = vault_data["entries"]
    if not entries:
        print(" Vault is empty.")
        return
    
    print(f"\nTotal entries: {len(entries)}")
    print("-" * 40)
    for idx, entry in enumerate(entries, 1):
        print(f"{idx}. {entry['service']} (User: {entry['username']})")


def search_entries(vault_data: dict):
    print("\n--- Search Entries ---")
    query = input("Enter search keyword: ").strip().lower()
    if not query:
        print(" Search query cannot be empty.")
        return
    
    results = [e for e in vault_data["entries"] if query in e["service"].lower() or query in e["username"].lower()]
    
    if not results:
        print(" No matching entries found.")
        return
    
    print(f"\nFound {len(results)} matching entries:")
    for entry in results:
        print(f"   - {entry['service']} (User: {entry['username']})")


# ---------------------- Main Entry Point ----------------------

def main():
    print(" Welcome to the Secure Password Manager!")
    
    # Check if vault exists
    if not os.path.exists(VAULT_FILE):
        print("\n🆕 First time setup. Please create your Master Password.")
        master_pw = getpass.getpass("Create Master Password: ").strip()
        confirm_pw = getpass.getpass("Confirm Master Password: ").strip()
        if master_pw != confirm_pw:
            print(" Passwords do not match. Exiting.")
            sys.exit(1)
        if len(master_pw) < 4:
            print(" Master password must be at least 4 characters long.")
            sys.exit(1)
        # Create empty vault
        vault_data = {"entries": []}
        save_vault(vault_data, master_pw)
        print(" Vault created successfully!")
    else:
        # Authenticate
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            master_pw = getpass.getpass("Enter Master Password: ").strip()
            try:
                with open(VAULT_FILE, "rb") as f:
                    encrypted_data = f.read()
                vault_data = decrypt_vault(encrypted_data, master_pw)
                break  # Success
            except ValueError:
                print(f" Wrong password! Attempts left: {max_attempts - attempt}")
                if attempt == max_attempts:
                    print(" Too many failed attempts. Exiting.")
                    sys.exit(1)
    
    # Command Loop
    while True:
        display_menu()
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            retrieve_entry(vault_data)
        elif choice == '2':
            add_entry(vault_data, master_pw)
            # Reload vault after adding to keep session updated (though we updated it)
            # Better to reload from disk or keep the updated dict. We'll pass the dict around.
            # Actually, let's just reload the vault_data to ensure consistency.
            with open(VAULT_FILE, "rb") as f:
                vault_data = decrypt_vault(f.read(), master_pw)
        elif choice == '3':
            delete_entry(vault_data, master_pw)
            with open(VAULT_FILE, "rb") as f:
                vault_data = decrypt_vault(f.read(), master_pw)
        elif choice == '4':
            list_entries(vault_data)
        elif choice == '5':
            search_entries(vault_data)
        elif choice == '6':
            print(" Goodbye! Your secrets are safe.")
            sys.exit(0)
        else:
            print(" Invalid choice. Please select 1-6.")


# ---------------------- Corrected Save / Encrypt Logic -------
# (Defining these after main so they can access constants, but better to define before main.
# I will place the corrected versions just before main.)

def save_vault(data: dict, master_password: str):
    """Encrypts the vault data with a fresh salt and writes to file."""
    # Generate a random salt and nonce inside the encryption function
    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    encrypted_data = salt + nonce + ciphertext
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)


def decrypt_vault(encrypted_data: bytes, master_password: str) -> dict:
    """Decrypts the vault and returns the JSON dict."""
    if len(encrypted_data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Invalid vault file format.")
    
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]
    
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        raise ValueError("Decryption failed. Wrong master password or corrupted data.") from e


if __name__ == "__main__":
    main()
