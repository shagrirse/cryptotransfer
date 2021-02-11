# Import OS to get filepaths
import os
# Import regex for checking
import re
# Hashlib to hash and obtain digest
from hashlib import sha256
# AES to encrypt/decrypt
from Cryptodome.Cipher import AES
# Random bytes to generate nonce
from Cryptodome.Random import get_random_bytes
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
# Bcrypt to check passwords
import bcrypt
# Define relative path name
dirname = os.path.dirname(__file__)
# Font Styles (Colours and Colour of Background)
# Red Bold Font with Red Background
redHighlight = "\x1b[1;37;41m"
# Default Font Styles
normalText = "\x1b[0;37;40m"

# AES Encrypt and Decrypt for static data stored on server
def AESEncrypt(text, key, BLOCK_SIZE = 16):
    # Generate nonce
    nonce = get_random_bytes(12)
    # Create a new AES cipher object for encryption
    cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)  # new AES cipher using key generated
    # Encrypt the data
    cipher_text_bytes = cipher.encrypt(pad(text,BLOCK_SIZE)) # encrypt data
    # Append nonce to the back of the encrypted data
    cipher_text_bytes = cipher_text_bytes + nonce
    # Return encrypted data
    return cipher_text_bytes

def AESDecrypt(cipher_text_bytes, key, BLOCK_SIZE = 16):
    cipher_text_bytes, nonce = cipher_text_bytes[:-12] , cipher_text_bytes[-12:]
    # create a new AES cipher object with the same key and mode
    my_cipher = AES.new(key,AES.MODE_CTR, nonce = nonce)
    # Now decrypt the text using your new cipher
    decrypted_text_bytes = unpad(my_cipher.decrypt(cipher_text_bytes),BLOCK_SIZE)
    # Print the message in UTF8 (normal readable way
    return decrypted_text_bytes

# Function to select file from user's choice and display items after decryption
def selectFile():
    # Getting a password input from the user
    password_input = input("Please enter a password: ")
    password_input = sha256(password_input.encode('utf-8')).hexdigest()
    # Trying to open file
    if os.path.exists(os.path.join(dirname, "database/passwd.txt")):
        file = ((open(os.path.join(dirname, "database/passwd.txt"), "r+")).readline()).encode('utf-8')
        # Checking password using BCRYPT
        while True:
            # If the user has entered an invalid password, the codes below will execute
            if not bcrypt.checkpw(password_input.encode('utf-8'), file):
                print(f"{redHighlight}You have entered an invalid password{normalText}")
                password_input = input("Please enter a password: ")
                password_input = sha256(password_input.encode('utf-8')).hexdigest()
            # If the user has entered a valid password, the codes below will execute
            else:
                # Define files listed, remove key and passwd.txt
                files = os.listdir(os.path.dirname(os.path.join(os.path.dirname(__file__), f"database/")))
                files.remove('key')
                files.remove('passwd.txt')
                # Print available files to view to user
                for file in files:
                    print(file)
                # Prompt user for choice, validate with regex
                choice = input("Please enter in a choice of file: ")
                while not re.match(r"result-((2([0-4]\d|5[0-5])|[01]?\d?\d)\.){3}(2([0-4]\d|5[0-5])|[01]?\d?\d)-[\d]+-[\d]+-[\d]+_[\d]{4}", choice):
                    choice = input("Error. Please enter in a choice of file: ")

                # Defining filepath file in database
                filepath = os.path.join(dirname + "/database/", choice)

                # Open file and read after decryption
                with open(filepath, "rb") as f:
                    data = f.read()
                    encryptedKey = open(os.path.join(dirname, "database/key"), 'rb+').read()
                    decryptedKey = AESDecrypt(encryptedKey, sha256('passwordpassword1'.encode('utf-8')).digest())
                    decryptedData = AESDecrypt(data, decryptedKey)
                    print("\n" + decryptedData.decode() + "\n")
                break
    else:
        print("You have not launched the server before. Please launch the server to setup your password.")

# Main program
if __name__ == '__main__': selectFile()

"""
██████╗  ██████╗ ███╗   ██╗███████╗    ██████╗ ██╗   ██╗    ██████╗  █████╗ ███╗   ██╗███████╗███████╗██╗     
██╔══██╗██╔═══██╗████╗  ██║██╔════╝    ██╔══██╗╚██╗ ██╔╝    ██╔══██╗██╔══██╗████╗  ██║╚══███╔╝██╔════╝██║     
██║  ██║██║   ██║██╔██╗ ██║█████╗      ██████╔╝ ╚████╔╝     ██║  ██║███████║██╔██╗ ██║  ███╔╝ █████╗  ██║     
██║  ██║██║   ██║██║╚██╗██║██╔══╝      ██╔══██╗  ╚██╔╝      ██║  ██║██╔══██║██║╚██╗██║ ███╔╝  ██╔══╝  ██║     
██████╔╝╚██████╔╝██║ ╚████║███████╗    ██████╔╝   ██║       ██████╔╝██║  ██║██║ ╚████║███████╗███████╗███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝    ╚═╝       ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝
"""