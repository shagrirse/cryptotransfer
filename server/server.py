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
ADDRESS = ("127.0.0.1", 8888) # Store server IP and port number in the 'ADDRESS' variable
DC_MSG = "!DISCONNECT FROM SERVER!" # Disconnect message sent from client to server to drop session
cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "server\menu_today.txt"
default_save_base = "result-"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
DiffieHellmanKey = pyDH.DiffieHellman(5)
def diffieHellmanKeyExchange():
    # Generating client public key
    serverDHPublicKey = DiffieHellmanKey.gen_public_key()
    # Returning the value of client public key
    return serverDHPublicKey

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
    decrypted_text = decrypted_text_bytes.decode()
    return decrypted_text

# Transit codes
# Open RSA public key generated from Client
def ClientRSAPublicKeyreceive(conn):
    receivedClientPublicRSAKey = RSA.import_key(receive_data(conn))
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
    loop = True
    # Returning client RSA private key
    return serverRSAKeyPair

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
    decryptedServerDHPublicKey = (RSACipher.decrypt(serverDHPublicKey))
    # Returning decrypted client Diffle-Hellman public key
    return decryptedServerDHPublicKey

# A function that verifies the signature of the data received from server
def digitalSignatureVerifier(clientDigest, clientPublicKey, clientSignature):
    # Verifying the signature of AES Encrypted Data received from Server with the server public key of the RSA key pair
    verifier = pkcs1_15.new(clientPublicKey)
    try:
        # If the signaature is valid, the function will return True
        verifier.verify(clientDigest, clientSignature)
        return True
    except:
        # If the signaature is not valid, the function will return False
        return False

# A function that performs Diffle-Hellman Key Exchange Calculations
def diffieHellmanKeyExchangeCalculations(clientDHPublicKey):
    # Generating session key
    sessionKey = DiffieHellmanKey.gen_shared_key(clientDHPublicKey)
    # Hashing the session key to be a AES 256-bit session key
    AESSessionKey = sha256(sessionKey.encode()).digest()
    # Returning the value of AES Session Key
    return AESSessionKey

# A function that verifies the HMAC of the data received from server
def HMACVerifier(HMACReceived, encryptedDataReceived, clientDHPublicKey):
    # HMAC key is the same as the AES session key
    HMACKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
    # AES Encrypted Data received from Server
    data = encryptedDataReceived
    # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
    HMAC = hmac.new(HMACKey, data, digestmod="sha512")
    # If the HMAC generated matches to the value of HMAC received, the function will return True
    if HMAC == HMACReceived:
        return True
    # If the HMAC generated does not match to the value of HMAC received, the function will return False
    else:
        return False

# A function that extracts all the encrypted data from a data class called serverEncryptedPayload
def encryptedPayloadReceived(clientEncryptedPayload):
    # Instantiating the serverEncryptedPayload class to serverPayload variable
    clientPayload = clientEncryptedPayload
    # Encrypted data from server
    encryptedDataReceived = clientPayload.encryptedFile
    # HMAC from server
    HMACReceived = clientPayload.HMAC
    # Server Digest
    serverDigest = clientPayload.digest
    # Server public key
    serverPublicKey = clientPayload.serverPublicKey
    # Server digital signature
    serverSignature = clientPayload.digitalSignature
    # Returning the payload encrypted data received from the server
    return encryptedDataReceived, HMACReceived, serverDigest, serverPublicKey, serverSignature

# Hash check for message sent from client to server
def hashcheck(conn, intendedMessage, addr):
    clientMessage = (receive_data(conn))
    if not (clientMessage == sha256(intendedMessage.encode()).hexdigest()):
        print(f"The message from the client is invalid or has been tampered with. Closing connection from client {addr[0]}:{addr[1]}...")
        conn.close()
        return False
    else: return True

class clientEncryptedPayload:
    def __init__(self):
        self.encryptedFile = ""
        self.HMAC = ""
        self.digitalSignature = ""
        self.clientPublicKey = b""
        self.digest = ""

# A function that stores all the encrypted data to a data class called clientEncryptedPayload
def encryptedPayloadSent(clientDHPublicKey, AESSessionKey):
    # AES Operation for files sent over the internet
    # A function that encrypts the client encrypted payload with server RSA public key

    with open("menu_today.txt", "rb") as file:
        data = file.read()
        file.close()

    # A function that generates a HMAC-SHA512 of a file
    def HMACOperation():
        # HMAC key is the same as the AES session key
        HMACKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
        print(data)
        # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
        HMAC = hmac.new(HMACKey, data, digestmod="sha512")
        # Returning a HMAC-SHA512 in bytes
        return HMAC.hexdigest()
    
    # A function that signs a AES Encrypted Data
    def digitalSignatureOperation():
        # Import SHA512 from Cryptodome hash
        from Cryptodome.Hash import SHA512
        # Generating the key pair for client
        serverRSAKeyPair = RSA.generate(2048)
        # Extracting client public key from the generated key pair
        serverPublicKey = serverRSAKeyPair.publickey()
        # Generating SHA-512 digest of the AES encrypted data
        digest = SHA512.new(data=data)
        # Signing the SHA-512 digest of the AES encrypted data with the private key of the RSA key pair
        signer = pkcs1_15.new(serverRSAKeyPair)
        signature = signer.sign(digest)
        # Returning the digest, client public key and digital signature of a AES Encrypted Data in bytes
        return digest, serverPublicKey, signature

    # Instantiating the clientEncryptedPayload class to payload variable
    payload = clientEncryptedPayload()
    # Assigning the value returned by AESOperation function to the class
    payload.encryptedFile = data
    # Assigning the value returned by HMACOperation function to the class
    payload.HMAC = HMACOperation()
    digitalSignature = digitalSignatureOperation()
    # Assigning the value returned by digitalSignatureOperation function to the class
    payload.digitalSignature = digitalSignature[2]
    # Assigning the value returned by digitalSignatureOperation function to the class
    payload.clientPublicKey = (digitalSignature[1]).export_key()
    # Assigning the value returned by digitalSignatureOperation function to the class
    payload.digest = (digitalSignature[0]).digest()
    # Returning the payload encrypted data to be sent to the server
    return AESEncrypt(pickle.dumps(payload), AESSessionKey)

def handler(conn, addr, passwd):
    now = datetime.datetime.now()
    sessionServerRSAPrivateKey = generateServerRSAKeyPair(conn)
    # Indicating that the server has generated the key and sent public key to client
    time.sleep(2)
    print(f"Server's RSA public key has been generated and sent to the client {addr[0]}:{addr[1]}\n")
    sessionClientRSAPublicKey = ClientRSAPublicKeyreceive(conn)
    # Indicating that the data has been received from the client
    print(f"Client's Public RSA key (Client {addr[0]}:{addr[1]}) has been received!\n")
    # Send the encrypted diffie hellman key to the client, encrypted with the client's public RSA key
    serverDHPublicKey = encryptDiffie(diffieHellmanKeyExchange(), sessionClientRSAPublicKey)
    send(serverDHPublicKey, conn)
    print(f"Diffie Hellman key has been generated and sent to the client (Client {addr[0]}:{addr[1]})\n")
    # Receive client's public DH key and decrypt it with server's private RSA key
    clientEncryptedDHPublicKey = receive_data(conn)
    clientDHPublicKey = int((decryptDiffieHellman(clientEncryptedDHPublicKey, sessionServerRSAPrivateKey)))
    AESSessionKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
    print(f"Client's ({addr[0]}:{addr[1]}) Diffie Hellman public key has been received!\n")
    # Receive data from client, CMD_GETMENU
    if hashcheck(conn, cmd_GET_MENU, addr): 
        # Send menuPayload with 'clientRSAPublicKey', but it is actually server's generated public key. Same attribute type to make them recognizable in each other's program
        menuPayload = encryptedPayloadSent(clientDHPublicKey, AESSessionKey)
        send(menuPayload, conn)
        # TODO: Decryption of payload using AES
    print(f"Client's ({addr[0]}:{addr[1]}) Menu of the day command has been received and its integrity verified. Sending encrypted menu to client!\n")
    # clientMessage = encryptedPayloadReceived(decryptPayloadwithRSA(receive_data(conn), sessionServerRSAPrivateKey))
    # Send menu.txt to client
    # while True:
    #     try:
    #         message = receive_data(conn)
    #         if type(message) == pyDH.DiffieHellman:
    #             # TODO: Generate DH public key and send to client
    #             print()
    #         elif cmd_GET_MENU in message: # ask for menu
    #             src_file = open(default_menu,"rb")
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