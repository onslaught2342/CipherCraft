
---

# **Encryption Program**

A secure encryption tool combining **RSA** and **AES** algorithms for protecting sensitive data and files. This program provides robust encryption, decryption, key management, and file obfuscation features for improved security.

---

## **Table of Contents**

1. [Introduction](#introduction)  
2. [Features](#features)  
3. [Requirements](#requirements)  
4. [Installation](#installation)  
5. [Usage Guide](#usage-guide)  
   - [Key File Initialization](#key-file-initialization)  
   - [Encrypting Data](#encrypting-data)  
   - [Decrypting Data](#decrypting-data)  
   - [Encrypting Files](#encrypting-files)  
   - [Decrypting Files](#decrypting-files)  
6. [How It Works](#how-it-works)  
7. [Security Measures](#security-measures)  
8. [Contributing](#contributing)  
9. [License](#license)  

---

## **Introduction**

This program handles secure encryption and decryption of data using **AES** (for symmetric encryption) and **RSA** (for asymmetric encryption). Key management is simplified with obfuscated key files that include RSA key pairs and AES keys, optionally secured with a password.

---

## **Features**

- **AES Encryption**: Encrypts and decrypts data or files using a 256-bit symmetric key.  
- **RSA Key Management**: Uses a 4096-bit RSA key pair to secure AES keys.  
- **Obfuscation**: Adds Base64 encoding and reversible string manipulation for additional protection of key files.  
- **File Encryption**: Supports encrypting and decrypting files directly with `.enc` extensions.  
- **Key File Hashing**: Enhances AES key security by integrating a hash of the key file for integrity verification.  

---

## **Requirements**

- **Python 3.x**  
- **cryptography library**: Install via `pip install cryptography`.  

---

## **Installation**

1. Clone or download the script to your project directory.  
2. Install required Python dependencies:  
   ```bash
   pip install cryptography
   ```

---

## **Usage Guide**

### **Key File Initialization**

Generate a key file if one does not exist.  
- Specify a path for the key file (e.g., `keyfile.key`).  
- Optionally provide a password to secure the key file.  

```python
initialize_key_file("keyfile.key", "your-secure-password")
```

### **Encrypting Data**

Encrypt strings or binary data with the following function:  

```python
encrypt_data("keyfile.key", "your-password", b"Your sensitive data")
```

Output: A Base64-encoded string containing the encrypted data.

### **Decrypting Data**

Retrieve and decrypt previously encrypted strings or binary data:  

```python
decrypt_data("keyfile.key", "your-password", "encrypted_data_string")
```

Output: The original unencrypted data.

### **Encrypting Files**

Encrypt files directly by providing their file path:  

```python
encrypt_file("keyfile.key", "your-password", "example.txt")
```

The encrypted file is saved with an `.enc` extension (e.g., `example.txt.enc`).

### **Decrypting Files**

Decrypt previously encrypted `.enc` files:  

```python
decrypt_file("keyfile.key", "your-password", "example.txt.enc")
```

The decrypted file is saved without the `.enc` extension (e.g., `example.txt`).

---

## **How It Works**

### Key Management
1. **RSA Key Pair**: Generates a 4096-bit private and public key pair.  
2. **AES Key**: A 256-bit AES key is created and encrypted using the RSA public key.  
3. **Key File Obfuscation**: The private key, public key, and encrypted AES key are stored in an obfuscated file secured with an optional password.

### Encryption Workflow
- **AES Encryption**: Data or files are encrypted using the AES key in **CFB mode** with a random initialization vector (IV).  
- **RSA Encryption**: The AES key is encrypted with the RSA public key and stored for decryption purposes.  

### Decryption Workflow
- **RSA Decryption**: The AES key is decrypted using the RSA private key.  
- **AES Decryption**: Encrypted data or files are decrypted using the AES key.  

### Key File Hashing
- Enhances AES key security by appending a SHA-256 hash of the key file to the AES key during encryption and decryption.

---

## **Security Measures**

- **RSA 4096-bit Keys**: Secure key exchange and AES key protection.  
- **AES 256-bit Keys**: Ensures strong encryption of data.  
- **Key Obfuscation**: Protects sensitive key file contents with Base64 encoding and string reversal.  
- **File Hashing**: Prevents unauthorized modifications by validating key file integrity.  
- **Error Handling**: Gracefully handles missing files, incorrect passwords, and decryption errors.  

---

## **Contributing**

Contributions are welcome! If you have ideas for improvements or find bugs, feel free to submit an issue or a pull request.

---

## **License**

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**. See `LICENSE` for details.

--- 
