import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC


# Helper function to obfuscate data
def obfuscate(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8')[::-1]

# Helper function to deobfuscate data
def deobfuscate(data: str) -> bytes:
    return base64.urlsafe_b64decode(data[::-1])

# Derive encryption key from passphrase
def derive_key_from_passphrase(passphrase: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# AES encryption
def aes_encrypt(data: bytes, key: bytes):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext

# AES decryption
def aes_decrypt(ciphertext: bytes, key: bytes):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# HMAC for integrity
def generate_hmac(data: bytes, key: bytes):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac(data: bytes, hmac_value: bytes, key: bytes):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(hmac_value)

# Generate secure AES key
def generate_aes_key(key_length=32):
    return os.urandom(key_length)

# Generate RSA key pair
def generate_rsa_keypair(key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# RSA encryption
def rsa_encrypt(data: bytes, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# RSA decryption
def rsa_decrypt(ciphertext: bytes, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Save the .key file securely
def save_key_file(file_path, passphrase, private_key, public_key, encrypted_aes_key):
    salt = os.urandom(16)
    encryption_key = derive_key_from_passphrase(passphrase, salt)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    content = b"".join([
        salt,
        private_bytes,
        public_bytes,
        encrypted_aes_key
    ])
    encrypted_content = aes_encrypt(content, encryption_key)
    with open(file_path, 'wb') as key_file:
        key_file.write(encrypted_content)

# Load the .key file securely
def load_key_file(file_path, passphrase):
    with open(file_path, 'rb') as key_file:
        encrypted_content = key_file.read()
    salt = encrypted_content[:16]
    encryption_key = derive_key_from_passphrase(passphrase, salt)
    content = aes_decrypt(encrypted_content[16:], encryption_key)
    private_key = serialization.load_pem_private_key(
        content[16:content.find(b'-----END PRIVATE KEY-----') + 25],
        password=None,
        backend=default_backend()
    )
    public_key = serialization.load_pem_public_key(
        content[content.find(b'-----BEGIN PUBLIC KEY-----'):content.find(b'-----END PUBLIC KEY-----') + 24],
        backend=default_backend()
    )
    encrypted_aes_key = content[content.rfind(b'-----END PUBLIC KEY-----') + 24:]
    return private_key, public_key, encrypted_aes_key

# Hash the .key file
def hash_key_file(file_path):
    with open(file_path, 'rb') as key_file:
        return hashlib.sha256(key_file.read()).digest()

# Initialize or load the .key file
def initialize_key_file(file_path, passphrase):
    if not os.path.exists(file_path):
        print("Key file not found. Generating a new one...")
        aes_key = generate_aes_key()
        private_key, public_key = generate_rsa_keypair()
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)
        save_key_file(file_path, passphrase, private_key, public_key, encrypted_aes_key)
        print(f"New key file generated and saved at {file_path}.")
    else:
        print(f"Key file found at {file_path}. Using existing keys.")

# Encrypt data
def encrypt_data(file_path, passphrase):
    private_key, public_key, encrypted_aes_key = load_key_file(file_path, passphrase)
    aes_key = rsa_decrypt(encrypted_aes_key, private_key)
    key_file_hash = hash_key_file(file_path)
    enhanced_aes_key = hashlib.sha256(aes_key + key_file_hash).digest()

    data = input("Enter the data to encrypt: ").encode()
    ciphertext = aes_encrypt(data, enhanced_aes_key)
    hmac_value = generate_hmac(ciphertext, enhanced_aes_key)
    print("Encrypted data:", base64.urlsafe_b64encode(ciphertext + hmac_value).decode())

# Decrypt data
def decrypt_data(file_path, passphrase):
    private_key, public_key, encrypted_aes_key = load_key_file(file_path, passphrase)
    aes_key = rsa_decrypt(encrypted_aes_key, private_key)
    key_file_hash = hash_key_file(file_path)
    enhanced_aes_key = hashlib.sha256(aes_key + key_file_hash).digest()

    encrypted_input = input("Enter the encrypted data to decrypt: ")
    encrypted_data = base64.urlsafe_b64decode(encrypted_input)
    ciphertext, hmac_value = encrypted_data[:-32], encrypted_data[-32:]

    verify_hmac(ciphertext, hmac_value, enhanced_aes_key)
    plaintext = aes_decrypt(ciphertext, enhanced_aes_key)
    print("Decrypted data:", plaintext.decode())

# Main program
def main():
    file_path = input("Enter key file path (default: encryption.key): ") or "encryption.key"
    passphrase = input("Enter passphrase for the key file: ")

    initialize_key_file(file_path, passphrase)

    while True:
        print("\nChoose an action:")
        print("1. Encrypt Data")
        print("2. Decrypt Data")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            encrypt_data(file_path, passphrase)
        elif choice == "2":
            decrypt_data(file_path, passphrase)
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
