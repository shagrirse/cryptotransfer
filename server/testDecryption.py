import bcrypt
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad

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

with open(r"C:\Work\acgfuck\server\database\result-127.0.0.1-2021-02-11_0859", "rb") as f:
    data = f.read()
    print(data)
    encryptedKey = open(r"C:\Work\acgfuck\server\database\key", 'rb').read()
    decryptedKey = AESDecrypt(encryptedKey, sha256('passwordpassword1'.encode('utf-8')).digest())
    decryptedData = AESDecrypt(data, decryptedKey)
    print(decryptedData)