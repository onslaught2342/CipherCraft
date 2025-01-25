**Encryption Algorithm**
=======================

A secure encryption program using RSA and AES algorithms to protect user data.

### Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Usage](#usage)
5. [Code Explanation](#code-explanation)
6. [Security Measures](#security-measures)
7. [Contributing](#contributing)
8. [License](#license)

### Introduction
This encryption program uses a combination of RSA and AES algorithms to provide secure encryption and decryption of user data. The program generates a key file that stores the RSA private and public keys, as well as an encrypted AES key.

### Features

* Generates a key file with RSA private and public keys, and an encrypted AES key
* Encrypts and decrypts user data using AES algorithm
* Uses HMAC to verify the integrity of the encrypted data
* Uses a passphrase to protect the key file

### Requirements

* Python 3.x
* cryptography library (`pip install cryptography`)

### Usage

1. Run the program and enter the key file path (default: `encryption.key`) and passphrase.
2. Choose an action:
	* Encrypt Data: Enter the data to encrypt, and the program will display the encrypted data.
	* Decrypt Data: Enter the encrypted data to decrypt, and the program will display the decrypted data.
	* Exit: Quit the program.

### Code Explanation

The program consists of several functions:

* `generate_aes_key`: Generates a random AES key.
* `generate_rsa_keypair`: Generates an RSA key pair.
* `save_key_file`: Saves the key file with the RSA private and public keys, and the encrypted AES key.
* `load_key_file`: Loads the key file and returns the RSA private and public keys, and the encrypted AES key.
* `encrypt_data`: Encrypts user data using the AES algorithm.
* `decrypt_data`: Decrypts user data using the AES algorithm.
* `main`: The main program loop that handles user input and actions.

### Security Measures

* The program uses a secure passphrase to protect the key file.
* The AES key is encrypted using the RSA public key.
* The HMAC algorithm is used to verify the integrity of the encrypted data.
* The program uses a secure random number generator to generate the AES key.

### Contributing

Contributions are welcome! Please submit a pull request with your changes.

### License

This program is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0). See LICENSE for details.
