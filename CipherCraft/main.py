from algo import (
    clear_screen,
    decrypt_data,
    decrypt_file,
    encrypt_data,
    encrypt_file,
    initialize_key_file,
)
import sys


def main():
    global key_path
    global password
    key_path = "encryption.key"
    password = input(
        "\nEnter the password to unlock your private key or to create a new one (leave blank if not set): "
    )
    initialize_key_file(key_path, password)

    try:
        while True:
            clear_screen()
            print("================================")
            print("\n=== Secure Encryption System ===")
            print("================================")
            print()
            print("\n=== Menu ===")
            print("\n=== Text Encryption ===")
            print("1. Encrypt Data")
            print("2. Decrypt Data")
            print("\n=== File Encryption ===")
            print("3. Encrypt File")
            print("4. Decrypt File")
            print("5. Exit")

            choice = input("Choose an option (1/2/3/4/5): ").strip()
            if choice == "1":
                data = input("Enter the data to encrypt: ").encode()
                encrypt_data(key_path, password, data)
                input("\nPress Enter to return to the menu...")
            elif choice == "2":
                encrypted_data = input("Enter the encrypted data to decrypt: ")
                decrypt_data(key_path, password, encrypted_data)
                input("\nPress Enter to return to the menu...")
            elif choice == "3":
                file_path = input("Enter the file path to encrypt: ")
                encrypt_file(key_path, password, file_path)
                input("\nPress Enter to return to the menu...")
            elif choice == "4":
                file_path = input("Enter the file path to decrypt: ")
                decrypt_file(key_path, password, file_path)
                input("\nPress Enter to return to the menu...")
            elif choice == "5":
                print("👋 Exiting. Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please try again.")
                input("\nPress Enter to return to the menu...")

    except KeyboardInterrupt:
        print("\n❌ Program interrupted by user. Exiting gracefully.")
        sys.exit(0)  # Proper exit


if __name__ == "__main__":
    main()
