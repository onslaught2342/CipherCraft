import base64
import hashlib
import os
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def clear_screen():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def sanitize_path(path):
    return re.sub(r'[^a-zA-Z0-9_.\-/]', '', path)

def obfuscate(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")[::-1]

def deobfuscate(data: str) -> bytes:
    return base64.urlsafe_b64decode(data[::-1])

def generate_aes_key(key_length=32):
    return os.urandom(key_length)


def aes_encrypt(data: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()


def generate_rsa_keypair(key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(data: bytes, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(ciphertext: bytes, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def save_key_file(key_path, private_key, public_key, encrypted_aes_key, password=None):
    key_path = sanitize_path(key_path)
    encryption_algorithm = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(key_path, "w") as key_file:
        key_file.write(obfuscate(private_bytes) + "\n")
        key_file.write(obfuscate(public_bytes) + "\n")
        key_file.write(obfuscate(encrypted_aes_key) + "\n")


def load_key_file(key_path, password=None):
    key_path = sanitize_path(key_path)
    with open(key_path, "r") as key_file:
        lines = key_file.readlines()
        private_key_data = deobfuscate(lines[0].strip())
        public_key_data = deobfuscate(lines[1].strip())
        encrypted_aes_key = deobfuscate(lines[2].strip())

        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password.encode() if password else None,
            backend=default_backend(),
        )
        public_key = serialization.load_pem_public_key(
            public_key_data, backend=default_backend()
        )
    return private_key, public_key, encrypted_aes_key


def hash_key_file(key_path):
    key_path = sanitize_path(key_path)
    with open(key_path, "rb") as key_file:
        file_data = key_file.read()
    return hashlib.sha256(file_data).digest()


def initialize_key_file(key_path, password):
    key_path = sanitize_path(key_path)
    if not os.path.exists(key_path):
        print("\n🔐 Key file not found. Generating a new one...")
        aes_key = generate_aes_key(32)
        private_key, public_key = generate_rsa_keypair()
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)
        save_key_file(key_path, private_key, public_key, encrypted_aes_key, password)
        print(f"✅ New key file generated and saved at {key_path}.")
    else:
        print(f"✅ Key file found at {key_path}. Using existing keys.")


def encrypt_data(key_path, password, data, print_data=True):
    key_path = sanitize_path(key_path)
    try:
        private_key, public_key, encrypted_aes_key = load_key_file(
            key_path, password if password else None
        )
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)
        key_file_hash = hash_key_file(key_path)
        enhanced_aes_key = hashlib.sha256(aes_key + key_file_hash).digest()
        encrypted_data = aes_encrypt(data, enhanced_aes_key)
        if print_data is True:
            print(
                "🔒 Encrypted data:", base64.urlsafe_b64encode(encrypted_data).decode()
            )
        else:
            return base64.urlsafe_b64encode(encrypted_data).decode()
    except Exception as e:
        print(f"❌ Error: {e}")


def decrypt_data(key_path, password, encrypted_data, print_data=True):
    key_path = sanitize_path(key_path)
    try:
        private_key, public_key, encrypted_aes_key = load_key_file(
            key_path, password if password else None
        )
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)
        key_file_hash = hash_key_file(key_path)
        enhanced_aes_key = hashlib.sha256(aes_key + key_file_hash).digest()
        encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data)
        decrypted_data = aes_decrypt(encrypted_data_bytes, enhanced_aes_key)
        if print_data is True:
            print("🔓 Decrypted data:", decrypted_data.decode())
        else:
            return decrypted_data.decode()
    except Exception as e:
        print(f"❌ Error: {e}")


def encrypt_file(key_path, password, file_path):
    key_path = sanitize_path(key_path)
    file_path = sanitize_path(file_path)
    try:
        with open(file_path, "rb") as data_file:
            data = data_file.read()
            encrypted_data = encrypt_data(key_path, password, data, print_data=False)
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, "wb") as encrypted_file:
                if encrypted_data:
                    encrypted_file.write(base64.urlsafe_b64decode(encrypted_data))
                else:
                    print("Error: No data was returned from encryption.")
            print(f"Encrypted file saved as {encrypted_file_path}")
    except Exception as e:
        print(f"❌ Error encrypting the file: {e}")


def decrypt_file(key_path, password, file_path):
    key_path = sanitize_path(key_path)
    file_path = sanitize_path(file_path)
    try:
        if file_path.endswith(".enc"):
            with open(file_path, "rb") as encrypted_data_file:
                encrypted_data = encrypted_data_file.read()
                decrypted_data = decrypt_data(
                    key_path,
                    password,
                    base64.urlsafe_b64encode(encrypted_data).decode(),
                    print_data=False,
                )
                decrypted_file_path = file_path[:-4]
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data.encode())
                print(f"Decrypted file saved as {decrypted_file_path}")
        else:
            print(
                "Invalid file format for decryption. Ensure the file is an encrypted .enc file."
            )
    except Exception as e:
        print(f"❌ Error decrypting the file: {e}")
