from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
import os
import sys
from PySide6 import QtCore, QtWidgets, QtGui
import random
import bcrypt
dirname = os.path.dirname(__file__)
# AES Encrypt for static data stored on server
def AESEncrypt(text, key, BLOCK_SIZE = 16):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)  # new AES cipher using key generated
    cipher_text_bytes = cipher.encrypt(pad(text,BLOCK_SIZE)) # encrypt data
    cipher_text_bytes = cipher_text_bytes + nonce
    return cipher_text_bytes

def AESDecrypt(cipher_text_bytes, key, BLOCK_SIZE = 16):
    cipher_text_bytes, nonce = cipher_text_bytes[:-12] , cipher_text_bytes[-12:]
    # create a new AES cipher object with the same key and mode
    my_cipher = AES.new(key,AES.MODE_CTR, nonce = nonce)
    # Now decrypt the text using your new cipher
    decrypted_text_bytes = unpad(my_cipher.decrypt(cipher_text_bytes),BLOCK_SIZE)
    # Print the message in UTF8 (normal readable way
    return decrypted_text_bytes

with open(os.path.join(dirname, 'database\\result-127.0.0.1-2021-02-09_2229'), "rb") as f:
    data = f.read()
    print(data)
    encryptedKey = open(os.path.join(dirname, 'database\key'), 'rb').read()
    decryptedKey = AESDecrypt(encryptedKey, sha256('passwordpassword1'.encode('utf-8')).digest())
    decryptedData = AESDecrypt(data, decryptedKey)
    print(decryptedData)

class Password(QtWidgets.QDialog):
    
    def __init__(self, parent=None):
        super(Password, self).__init__(parent)
        # Set window title
        title = "View Database"
        self.setWindowTitle(title)
        # Password Field widget
        self.edit = QtWidgets.QLineEdit("")
        # Button widget
        self.button = QtWidgets.QPushButton("Verify Password")
        # Create layout and add widgets
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.edit)
        layout.addWidget(self.button)
        # Read stylesheet from the qss file (similar to CSS but for Qt)
        _style = open(os.path.join(dirname, 'style.qss'), "r").read()
        self.setStyleSheet(_style)
        # Set dialog layout
        self.setLayout(layout)
        # Add button signal to verify the user's password
        self.button.clicked.connect(self.verifyPassword)

    # Greets the user
    def verifyPassword(self):
        # Instantiate hashed password as the text file of the bcrypt hashed password
        hashedPassword = open(os.path.join(dirname, "database/passwd.txt"), "r").read()
        # Make the password the userinput
        password = self.edit.text()
        # Hash the password the same process to compare both passwords
        userHashedPassword = sha256(password.encode()).hexdigest()
        # Creating a message box
        msg = QtWidgets.QMessageBox()
        if not bcrypt.checkpw(userHashedPassword.encode(), hashedPassword.encode()):
            msg.setText("Incorrect Password")
            msg.exec_()
        else:
            msg.setText("User Authenticated")
            msg.exec_()
            self.database()

if os.path.exists(os.path.join(dirname, "database/passwd.txt")):
    # Create the Qt Application
    app = QtWidgets.QApplication(sys.argv)
    # Create and show the form
    signinBox = Password()
    signinBox.resize(400, 300)
    signinBox.show()
    # Run the main Qt loop
    sys.exit(app.exec_())
# If password file is not found, server did not have an initial launch
else: print("Database has not been set up yet. Please ensure that you have launched the server once.")