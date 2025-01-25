import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Helper function to obfuscate data
def obfuscate(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8')[::-1]

# Helper function to deobfuscate data
def deobfuscate(data: str) -> bytes:
    return base64.urlsafe_b64decode(data[::-1])

# Generate a secure AES key
def generate_aes_key(key_length=32):
    return os.urandom(key_length)

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

# Save the .key file with obfuscated RSA keys and encrypted AES key
def save_key_file(file_path, private_key, public_key, encrypted_aes_key):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Write obfuscated content to file
    with open(file_path, 'w') as key_file:
        key_file.write(obfuscate(private_bytes) + "\n")
        key_file.write(obfuscate(public_bytes) + "\n")
        key_file.write(obfuscate(encrypted_aes_key) + "\n")

# Load and deobfuscate the .key file
def load_key_file(file_path):
    with open(file_path, 'r') as key_file:
        lines = key_file.readlines()
        private_key = serialization.load_pem_private_key(
            deobfuscate(lines[0].strip()),
            password=None,
            backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            deobfuscate(lines[1].strip()),
            backend=default_backend()
        )
        encrypted_aes_key = deobfuscate(lines[2].strip())
    return private_key, public_key, encrypted_aes_key

# Hash the .key file for added randomness
def hash_key_file(file_path):
    with open(file_path, 'rb') as key_file:
        file_data = key_file.read()
    return hashlib.sha256(file_data).digest()

# Initialize or load encryption keys
def initialize_key_file(file_path="encryption.key"):
    if not os.path.exists(file_path):
        print("Key file not found. Generating a new one...")
        aes_key = generate_aes_key(32)  # 256-bit AES key
        private_key, public_key = generate_rsa_keypair()
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)
        save_key_file(file_path, private_key, public_key, encrypted_aes_key)
        print(f"New key file generated and saved at {file_path}.")
    else:
        print(f"Key file found at {file_path}. Using existing keys.")

# Encrypt data
def encrypt_data(file_path="encryption.key"):
    # Load keys and decrypt AES key
    private_key, public_key, encrypted_aes_key = load_key_file(file_path)
    aes_key = rsa_decrypt(encrypted_aes_key, private_key)

    # Add randomness from the .key file hash
    key_file_hash = hash_key_file(file_path)
    enhanced_aes_key = hashlib.sha256(aes_key + key_file_hash).digest()

    # Encrypt user-provided data
    data = input("Enter the data to encrypt: ").encode()
    encrypted_data = aes_encrypt(data, enhanced_aes_key)
    print("Encrypted data:", base64.urlsafe_b64encode(encrypted_data).decode())

# Decrypt data
def decrypt_data(file_path="encryption.key"):
    # Load keys and decrypt AES key
    private_key, public_key, encrypted_aes_key = load_key_file(file_path)
    aes_key = rsa_decrypt(encrypted_aes_key, private_key)

    # Add randomness from the .key file hash
    key_file_hash = hash_key_file(file_path)
    enhanced_aes_key = hashlib.sha256(aes_key + key_file_hash).digest()

    # Decrypt user-provided data
    encrypted_data = input("Enter the encrypted data to decrypt: ")
    encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data)
    decrypted_data = aes_decrypt(encrypted_data_bytes, enhanced_aes_key)
    print("Decrypted data:", decrypted_data.decode())

# Main user interaction
def main():
    file_path = "encryption.key"
    initialize_key_file(file_path)
    
    while True:
        print("\nChoose an action:")
        print("1. Encrypt Data")
        print("2. Decrypt Data")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            encrypt_data(file_path)
        elif choice == "2":
            decrypt_data(file_path)
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
