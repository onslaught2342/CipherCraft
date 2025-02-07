import base64
import hashlib
import os
import re
import platform
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def sanitize_path(path):
    if platform.system() == "Windows":
        return re.sub(r"[^a-zA-Z0-9_ .:\\/-]", "", path)
    else:
        return re.sub(r"[^a-zA-Z0-9_./-]", "", path)


def obfuscate(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")[::-1]


def deobfuscate(data: str) -> bytes:
    return base64.urlsafe_b64decode(data[::-1])


def generate_aes_key(key_length=32):
    return os.urandom(key_length)


def aes_encrypt(data: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes):
    iv, encrypted_data = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


def generate_rsa_keypair(key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    return private_key, private_key.public_key()


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

    with open(key_path, "w") as key_file:
        key_file.write(
            obfuscate(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm,
                )
            )
            + "\n"
        )
        key_file.write(
            obfuscate(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            + "\n"
        )
        key_file.write(obfuscate(encrypted_aes_key) + "\n")


def load_key_file(key_path, password=None):
    key_path = sanitize_path(key_path)
    with open(key_path, "r") as key_file:
        lines = key_file.readlines()
        private_key = serialization.load_pem_private_key(
            deobfuscate(lines[0].strip()),
            password=password.encode() if password else None,
            backend=default_backend(),
        )
        public_key = serialization.load_pem_public_key(
            deobfuscate(lines[1].strip()), backend=default_backend()
        )
        return private_key, public_key, deobfuscate(lines[2].strip())


def hash_key_file(key_path):
    with open(sanitize_path(key_path), "rb") as key_file:
        return hashlib.sha256(key_file.read()).digest()


def initialize_key_file(key_path, password):
    key_path = sanitize_path(key_path)
    if not os.path.exists(key_path):
        print("\n🔐 Key file not found. Generating a new one...")
        aes_key = generate_aes_key()
        private_key, public_key = generate_rsa_keypair()
        save_key_file(
            key_path,
            private_key,
            public_key,
            rsa_encrypt(aes_key, public_key),
            password,
        )
        print(f"✅ New key file generated and saved at {key_path}.")
    else:
        print(f"✅ Key file found at {key_path}. Using existing keys.")


def encrypt_data(key_path, password, data, print_data=True):
    try:
        private_key, public_key, encrypted_aes_key = load_key_file(key_path, password)
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)
        encrypted_data = aes_encrypt(
            base64.b64encode(data.encode() if isinstance(data, str) else data),
            hashlib.sha256(aes_key + hash_key_file(key_path)).digest(),
        )
        result = base64.urlsafe_b64encode(encrypted_data).decode()
        if print_data:
            print("🔒 Encrypted data:", result)
        return result
    except Exception as e:
        print(f"❌ Error: {e}")


def decrypt_data(key_path, password, encrypted_data, print_data=True):
    try:
        private_key, public_key, encrypted_aes_key = load_key_file(key_path, password)
        aes_key = rsa_decrypt(encrypted_aes_key, private_key)
        decrypted_data = base64.b64decode(
            aes_decrypt(
                base64.urlsafe_b64decode(encrypted_data),
                hashlib.sha256(aes_key + hash_key_file(key_path)).digest(),
            )
        )
        if print_data:
            print("🔓 Decrypted data:", decrypted_data.decode(errors="ignore"))
        return decrypted_data
    except Exception as e:
        print(f"❌ Error: {e}")


def encrypt_file(key_path, password, file_path):
    try:
        with open(sanitize_path(file_path), "rb") as data_file:
            encrypted_data = encrypt_data(
                key_path, password, data_file.read(), print_data=False
            )
            if encrypted_data:
                with open(file_path + ".enc", "wb") as encrypted_file:
                    encrypted_file.write(base64.urlsafe_b64decode(encrypted_data))
                print(f"✅ Encrypted file saved as {file_path}.enc")
    except Exception as e:
        print(f"❌ Error encrypting file: {e}")


def decrypt_file(key_path, password, file_path):
    try:
        if not file_path.endswith(".enc"):
            print("❌ Invalid file format for decryption.")
            return
        with open(sanitize_path(file_path), "rb") as encrypted_file:
            decrypted_data = decrypt_data(
                key_path,
                password,
                base64.urlsafe_b64encode(encrypted_file.read()).decode(),
                print_data=False,
            )
            if decrypted_data:
                with open(file_path[:-4], "wb") as decrypted_output:
                    decrypted_output.write(decrypted_data)
                print(f"✅ Decrypted file saved as {file_path[:-4]}")
    except Exception as e:
        print(f"❌ Error decrypting file: {e}")
