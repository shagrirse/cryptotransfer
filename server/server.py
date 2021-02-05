import datetime
import pickle
import time
import bcrypt
from hashlib import sha256
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
import base64

ADDRESS = ("127.0.0.1", 8888) # Store server IP and port number in the 'ADDRESS' variable
DC_MSG = "!DISCONNECT FROM SERVER!" # Disconnect message sent from client to server to drop session
cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "server\menu_today.txt"
default_save_base = "result-"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)

def diffieHellmanKeyExchange():
    # Generating client public key
    serverDHPublicKey = pyDH.DiffieHellman(5).gen_public_key()
    # Returning the value of client public key
    return serverDHPublicKey

class clientEncryptedPayload:
    def __init__(self):
        self.encryptedFile = ""
        self.HMAC = ""
        self.digitalSignature = ""
        self.clientPublicKey = b""
        self.digest = ""

# Send function to send item to client
def send(message, s):
    msg = pickle.dumps(message)
    s.send(msg)
    
def receive_data(s):
    BUFF_SIZE = 8192
    data = b''
    while True:
        packet = s.recv(BUFF_SIZE)
        data += packet
        if len(packet) < BUFF_SIZE:
            break
    data = pickle.loads(data)
    return data

def AESEncrypt(text, key, BLOCK_SIZE = 16):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)  # new AES cipher using key generated
    cipher_text_bytes = cipher.encrypt(pad(text,BLOCK_SIZE)) # encrypt data
    cipher_text_bytes = cipher_text_bytes + nonce
    print(cipher_text_bytes)
    return cipher_text_bytes

def AESDecrypt(cipher_text_bytes, key, BLOCK_SIZE = 16):
    cipher_text_bytes, nonce = cipher_text_bytes[:-12] , cipher_text_bytes[-12:]
    # create a new AES cipher object with the same key and mode
    my_cipher = AES.new(key,AES.MODE_CTR, nonce = nonce)
    # Now decrypt the text using your new cipher
    decrypted_text_bytes = unpad(my_cipher.decrypt(cipher_text_bytes),BLOCK_SIZE)
    # Print the message in UTF8 (normal readable way
    decrypted_text = decrypted_text_bytes.decode()
    return decrypted_text

# Transit codes
# Open RSA public key generated from Client
def ClientRSAPublicKeyreceive(conn):
    receivedClientPublicRSAKey = RSA.import_key(receive_data(conn))
    # Indicating that the data has been received from the client
    print("Client's Public RSA key has been received!")
    # Return the RSA key
    return receivedClientPublicRSAKey

# Generate server RSA public key
def generateServerRSAKeyPair(conn):
    # Generate 4096-bit long server RSA Key pair
    serverRSAKeyPair = RSA.generate(4096)
    # Extracting server RSA public key
    serverRSAPublicKey = serverRSAKeyPair.publickey().export_key()
    # Sending information to the server
    send(serverRSAPublicKey, conn)
    # Indicating that the data has been sent to the server
    print("Server's RSA public key has been sent to the client!")

    # Returning client RSA private key
    return serverRSAKeyPair

# Encrypting the payload with CLIENT RSA public key
def encryptPayloadWithRSA(payload, clientPublicKey):
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(clientPublicKey)
    # Encrypting payload with server RSA public key
    payload = RSACipher.encrypt(payload)
    # Returning RSA encrypted payload
    return payload

# Decrypting the payload received from client with Server RSA Private Key
def decryptPayloadwithRSA(clientEncryptedPayload, serverPrivateKey):
    # Decrypt payload with server private key
    clientDecryptedPayload = clientEncryptedPayload.decrypt(serverPrivateKey)
    # Return the decrypted payload
    return clientDecryptedPayload

# Encrypt Diffie Hellman Public Key on Server
def encryptDiffie(serverDHPublicKey, clientPublicRSA):
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(clientPublicRSA)
    # Encrypting client Diffle-Hellman public key with client RSA public key
    encryptedclientDHPublicKey = RSACipher.encrypt(str(serverDHPublicKey).encode())
    # Returning encrypted client Diffle-Hellman public key
    return encryptedclientDHPublicKey

# A function that decrypts server Diffie-Hellman public key
def decryptDiffieHellman(serverDHPublicKey, serverRSAPrivateKey):
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(serverRSAPrivateKey)
    # Decrypting server Diffle-Hellman public key with client RSA private key
    decryptedServerDHPublicKey = RSACipher.decrypt(serverDHPublicKey)
    # Returning decrypted client Diffle-Hellman public key
    return decryptedServerDHPublicKey

def handler(conn, addr, passwd):
    now = datetime.datetime.now()
    sessionServerRSAPrivateKey = generateServerRSAKeyPair(conn)
    sessionClientRSAPublicKey = ClientRSAPublicKeyreceive(conn)

    send(encryptDiffie(diffieHellmanKeyExchange(), sessionClientRSAPublicKey), conn)
    clientDHPublicKey = decryptDiffieHellman(receive_data(conn), sessionServerRSAPrivateKey)
    print(clientDHPublicKey)
    # while True:
    #     try:
    #         message = receive_data(conn)
    #         if type(message) == pyDH.DiffieHellman:
    #             # TODO: Generate DH public key and send to client
    #             print()
    #         elif cmd_GET_MENU in message: # ask for menu
    #             src_file = open(default_menu,"rb")
    #             # TODO: Encryption
    #             conn.send(src_file)
    #             src_file.close()
    #         elif type(message) == clientEncryptedPayload:
    #             filename = default_save_base +  addr[0] + "-" + now.strftime("%Y-%m-%d_%H%M")
    #             dest_file = open("server/database/" + filename,"wb")
    #             print("lol")
    #             if not os.path.exists("server/database/key"):
    #                 random_key = get_random_bytes(32)
    #                 info_encrypted = AESEncrypt(message, random_key)
    #                 dest_file.write(info_encrypted)
    #             else:
    #                 print()
    #         break
    #     except:
    #         print(traceback.format_exc())

def start(passwd):
    server.listen()
    print(f"[LISTENING] SERVER IS LISTENING ON LOOPBACK ADDRESS")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handler, args=(conn, addr, passwd))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

def user_login():
    # Try to open file
    try:
        file = ((open("server/database/passwd.txt", "r")).readline()).encode('utf-8')
        password_input= input("Please enter a password: ")
        password_input = sha256(password_input.encode('utf-8')).hexdigest()
        passwd = sha256(password_input.encode('utf-8'))
        while True:
            if not bcrypt.checkpw(password_input.encode('utf-8'), file):
                password_input= input("Error. Please enter a password: ")
                password_input = sha256(password_input.encode('utf-8')).hexdigest()
            else:
                print("Login Successful. Server Starting...")
                time.sleep(2)
                start(passwd)
            
    # If file does not exist, prompt user to create login
    except Exception as e:
        print(e)
        print(f"-----Creation of Password-----\n[As this is your first time using the server, you will have to create a password which will be used for server-side encryption")
        password = input("Please enter a password: ")
        # Password must have more than 12 characters but lesser than 31, and must have a number. For the example, the password will be "passwordpassword1"
        while len(password) < 12 or len(password) > 30 or not any(map(lambda x: x.isnumeric(), [i for i in password])):
            password = input("Error. Please enter a valid password (More than 12 characters but less than 30. Must contain a number): ")
        else:
            print("You have created a password. Please remember this password for future use of the server to access files.")
            with open("server/database/passwd.txt", "w") as file:
                hashed = (sha256(password.encode('utf-8'))).hexdigest()
                passwd = sha256(password.encode('utf-8')).digest()
                hashed = bcrypt.hashpw(hashed.encode('utf-8'), bcrypt.gensalt())
                file.write(hashed.decode('utf-8'))
            time.sleep(2)
            start(passwd)
start(sha256('passwordpassword1'.encode('utf-8')))
# user_login()