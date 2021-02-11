# Importing os Module to get filepaths
import os
# Importing Regular Expression Module to perform input validation checks
import re
# Importing Hashlib Module for hashing and obtaining digest purposes
from hashlib import sha256
# Importing get_random_bytes function to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES
# Importing Pad and Unpad functions to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
# Importing bcrypt Module to perform password hashing operations
import bcrypt

# Font Styles (Colours and Colour of Background)
# Red Bold Font with Red Background
redHighlight = "\x1b[1;37;41m"
# Default Font Styles
normalText = "\x1b[0;37;40m"

# Defining relative path
dirname = os.path.dirname(__file__)


# A function that performs AES Decryption Operation
# AES block size is 128 bits or 16 bytes
def AESDecrypt(cipher_text_bytes, key, BLOCK_SIZE=16):
    # Extracting AES Encrypted Data,
    # Extracting AES Nonce
    cipher_text_bytes, nonce = cipher_text_bytes[:-12], cipher_text_bytes[-12:]
    # Instantiating AES cipher with the same key and mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Decrypting data
    decrypted_text_bytes = unpad(cipher.decrypt(cipher_text_bytes), BLOCK_SIZE)
    # Returning AES Unencrypted Data in bytes
    return decrypted_text_bytes


# A function that selects the file based on the user's choice and displays the file content after decryption
def selectFile():
    # Printing user interface
    print("\n█▀▄ ▄▀█ █▄█   █▀▀ █░░ █▀█ █▀ █ █▄░█ █▀▀   █░█ █ █▀▀ █░█░█ █▀▀ █▀█\n█▄▀ █▀█ ░█░   █▄▄ █▄▄ █▄█ ▄█ █ █░▀█ █▄█   ▀▄▀ █ ██▄ ▀▄▀▄▀ ██▄ █▀▄")
    print("\nPlease enter the password to view the day closing information stored in the database.")
    # Getting a password input from the user
    password_input = input("\nPlease enter a password: ")
    # Hashing the password input
    password_input = sha256(password_input.encode('utf-8')).hexdigest()
    # Trying to open the file
    if os.path.exists(os.path.join(dirname, "database/passwd.txt")):
        # File path for passwd.txt
        file = ((open(os.path.join(dirname, "database/passwd.txt"), "r+")
                 ).readline()).encode('utf-8')
        # Checking password using BCRYPT
        while True:
            # If the user has entered an invalid password, the codes below will execute
            if not bcrypt.checkpw(password_input.encode('utf-8'), file):
                print(
                    f"\n{redHighlight}You have entered an invalid password{normalText}")
                password_input = input("Please enter a password: ")
                password_input = sha256(
                    password_input.encode('utf-8')).hexdigest()
            # If the user has entered a valid password, the codes below will execute
            else:
                # Defining the files to be listed excluding remove the key and passwd.txt files
                files = os.listdir(os.path.dirname(os.path.join(
                    os.path.dirname(__file__), f"database/")))
                files.remove('key')
                files.remove('passwd.txt')
                # Printing the available files for the user to view
                print("\nFiles Available For Viewing:")
                for file in files:
                    print(file)
                # Prompting the user for his or her choice
                choice = input("\nPlease enter a choice of file: ")
                # Input validation with regular expression
                while not re.match(r"result-((2([0-4]\d|5[0-5])|[01]?\d?\d)\.){3}(2([0-4]\d|5[0-5])|[01]?\d?\d)-[\d]+-[\d]+-[\d]+_[\d]{4}", choice):
                    # Input validation failed
                    choice = input(
                        f"\n{redHighlight}Invalid choice selected!{normalText} Please enter a choice of file: ")

                # Input validation passed
                # Defining the file path of the file in the database that the user has selected
                filepath = os.path.join(dirname + "/database/", choice)

                # Indicating which file the user is viewing
                print(
                    "\n=================================================================")
                print(f"Viewing {choice} File Day End Information")
                print(
                    "=================================================================")

                # Opening the file and read the file after decryption
                with open(filepath, "rb") as f:
                    # Reading the encrypted file content
                    data = f.read()
                    # Getting the encrypted key from the key file
                    encryptedKey = open(os.path.join(
                        dirname, "database/key"), 'rb+').read()
                    # Decrypting the encrypted key using the user's password
                    decryptedKey = AESDecrypt(encryptedKey, sha256(
                        "passwordpassword1".encode('utf-8')).digest())
                    # Decrypting the file content using the decrypted key in the key file
                    decryptedData = AESDecrypt(data, decryptedKey)
                    # Printing the decrypted file content
                    print("\n" + decryptedData.decode() + "\n")
                break
    else:
        # If the user has not launched the server before, the system will prompt the user to launch the server first
        print("You have not launched the server before. Please launch the server to setup your password.")


# Main program
if __name__ == '__main__':
    selectFile()

# Acknowledgements
# Program Design:
"""
██████╗  ██████╗ ███╗   ██╗███████╗    ██████╗ ██╗   ██╗    ██████╗  █████╗ ███╗   ██╗███████╗███████╗██╗     
██╔══██╗██╔═══██╗████╗  ██║██╔════╝    ██╔══██╗╚██╗ ██╔╝    ██╔══██╗██╔══██╗████╗  ██║╚══███╔╝██╔════╝██║     
██║  ██║██║   ██║██╔██╗ ██║█████╗      ██████╔╝ ╚████╔╝     ██║  ██║███████║██╔██╗ ██║  ███╔╝ █████╗  ██║     
██║  ██║██║   ██║██║╚██╗██║██╔══╝      ██╔══██╗  ╚██╔╝      ██║  ██║██╔══██║██║╚██╗██║ ███╔╝  ██╔══╝  ██║     
██████╔╝╚██████╔╝██║ ╚████║███████╗    ██████╔╝   ██║       ██████╔╝██║  ██║██║ ╚████║███████╗███████╗███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝    ╚═╝       ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝
"""
# User Interface Design and Code Commenting: Gary
