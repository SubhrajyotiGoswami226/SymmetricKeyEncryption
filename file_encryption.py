from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

#ENCRYPTION FUNCTION
def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_CBC)  # Create a new cipher object
    iv = cipher.iv  # Get the initialization vector

    with open(input_file, 'rb') as f:
        plaintext = f.read()  # Read the plaintext

    # Pad the plaintext and encrypt
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)  # Write the IV and ciphertext to the output file

#DECRYPTION FUNCTION
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the first 16 bytes for the IV
        ciphertext = f.read()  # Read the remaining data

    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create a new cipher object with the IV
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(plaintext)  # Write the decrypted plaintext to the output file

#USER INTERFACE
def main():
    choice = input("Do you want to (e)ncrypt or (d)ecrypt a file? ").lower()
    if choice == 'e':
        input_file = input("Enter the path of the file to encrypt: ")
        output_file = input("Enter the path to save the encrypted file: ")
        
        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)  # Create the directory if it doesn't exist

        key = get_random_bytes(16)
        print(f"Your encryption key (keep it safe!): {key.hex()}")
        encrypt_file(input_file, output_file, key)
        print("File encrypted successfully.")
    elif choice == 'd':
        input_file = input("Enter the path of the file to decrypt: ")
        output_file = input("Enter the path to save the decrypted file: ")
        key = bytes.fromhex(input("Enter your encryption key (hex): "))
        decrypt_file(input_file, output_file, key)
        print("File decrypted successfully.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
