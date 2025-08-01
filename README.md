Lockbox CLI — Secure File Encryptor
====================================

Overview:
---------
Lockbox is a command-line tool to securely encrypt and decrypt files using AES-256-GCM encryption.
All encryption happens client-side with a password, and the ciphertext includes a secure salt and nonce.

Main Features:
--------------
- AES‑GCM encryption (256-bit)
- Scrypt key derivation for password safety
- Random salt & nonce per encryption
- Single binary blob output (.pv format)
- CLI-based usage (encrypt & decrypt)
- Password input hidden with getpass
- Clean exit & error handling
- End-to-end test case (round trip check)

How it Works:
-------------
Encryption:
1. Reads input file as bytes.
2. Generates a random salt and nonce.
3. Derives a 256-bit AES key from the password + salt using Scrypt.
4. Encrypts the file using AES-GCM (authenticated encryption).
5. Prepends a 3-byte magic header, salt, and nonce to the ciphertext.
6. Writes output to a .pv file.

Decryption:
1. Reads the .pv file and parses magic, salt, nonce, ciphertext.
2. Verifies the magic bytes.
3. Derives the key using the password + salt.
4. Decrypts using AES-GCM.
5. Writes the result back to the original filename (removes .pv).

Running the CLI:
----------------
To encrypt a file:
> python lockbox.py encrypt <filename>

To decrypt a file:
> python lockbox.py decrypt <filename>.pv

You’ll be prompted to enter a master password.

Running the Test:
-----------------
To validate that encryption & decryption works correctly:
> python test_lockbox.py

You should see:
> round trip test passed

Project Structure:
------------------
- lockbox.py         → Main encryption/decryption logic and CLI
- test_lockbox.py    → Round-trip unit test
- README.txt         → This file

Security Notes:
---------------
- Do not reuse passwords across files if you’re not storing the salt elsewhere.
- Don’t transmit passwords over insecure channels.
- Encrypting very large files may consume memory (entire file is read).

Why I Built This:
-----------------
This project is part of a larger Privacy‑First Family Photo Vault.
It helps me learn client-side encryption, password-based key derivation, and how secure file tools are built from scratch.

TODO (Next Steps):
------------------
- Add file overwrite protection
- Add progress indicator for large files
- Handle directory input (encrypt/decrypt folders)
- Support Web version with WebCrypto API (for the vault)
