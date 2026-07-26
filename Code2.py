def caesar_encrypt(text, shift):
    result = ""

    for char in text:
        # Encrypt uppercase letters
        if char.isupper():
            new_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            result += new_char

        # Encrypt lowercase letters
        elif char.islower():
            new_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            result += new_char

        # Keep spaces, numbers, and symbols unchanged
        else:
            result += char

    return result


def caesar_decrypt(text, shift):
    # Decryption is encryption with negative shift
    return caesar_encrypt(text, -shift)


def get_shift():
    while True:
        try:
            shift = int(input("Enter shift value (0-25): "))

            if 0 <= shift <= 25:
                return shift
            else:
                print("Shift must be between 0 and 25.")

        except ValueError:
            print("Please enter a valid number.")


def main():
    print("=" * 50)
    print("      CAESAR CIPHER ENCRYPTION TOOL")
    print("=" * 50)

    while True:
        print("\\nChoose an option:")
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            text = input("\\nEnter message to encrypt: ")
            shift = get_shift()

            encrypted = caesar_encrypt(text, shift)

            print("\\n--- ENCRYPTION RESULT ---")
            print(f"Original Message : {text}")
            print(f"Shift Value      : {shift}")
            print(f"Encrypted Text   : {encrypted}")

        elif choice == "2":
            text = input("\\nEnter message to decrypt: ")
            shift = get_shift()

            decrypted = caesar_decrypt(text, shift)

            print("\\n--- DECRYPTION RESULT ---")
            print(f"Encrypted Text   : {text}")
            print(f"Shift Value      : {shift}")
            print(f"Decrypted Text   : {decrypted}")

        elif choice == "3":
            print("\\nThank you for using the Caesar Cipher Tool!")
            break

        else:
            print("Invalid choice. Please select 1, 2, or 3.")


# Run the program
if __name__ == "__main__":
    main()
    
