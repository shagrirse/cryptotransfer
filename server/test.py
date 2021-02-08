import datetime
import pickle
import time
import bcrypt
from hashlib import sha256, sha512
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import os
import socket
import threading
import pyDH
import traceback
from Cryptodome.PublicKey import RSA
# Importing socket Module to perform socket operations
import socket
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES, PKCS1_OAEP
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
# Importing Digital Signature Module to perfrom Digital Signature operations
from Cryptodome.Signature import pkcs1_15
# Importing RSA Module to perfrom RSA operations
from Cryptodome.PublicKey import RSA
# Importing pickle Module for serialising Python objects
import pickle
# Importing Diffie-Hellman Key Exchange to perform Diffle-Hellman Key Exchange operations
import pyDH
# Importing HMAC Module to perform HMAC operations
import hmac

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

with open(r"C:\Work\acgfuck\server\database\result-127.0.0.1-2021-02-09_0227", "rb") as f:
    data = f.read()
    print(data)
    encryptedKey = open(r"C:\Work\acgfuck\server\database\key", 'rb').read()
    decryptedKey = AESDecrypt(encryptedKey, sha256('passwordpassword1'.encode('utf-8')).digest())
    decryptedData = AESDecrypt(data, decryptedKey)
    print(decryptedData)