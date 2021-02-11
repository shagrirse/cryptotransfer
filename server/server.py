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
# Relative path
dirname = os.path.dirname(__file__)
# Red Bold Font with Red Background
redHighlight = "\x1b[1;37;41m"
# Default Font Styles
normalText = "\x1b[0;37;40m"
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

# A function that sends information to the server
def send(message, s):
    # Serialising the information to be sent to the server
    msg = pickle.dumps(message)
    # Sending information to the server
    s.send(msg)
    
# A function that receives information from the server
def receive_data(s):
    # Setting buffer size
    BUFF_SIZE = 8192
    # Initialising data variable as an empty byte string
    data = b''
    while True:
        # Receiving information from the server
        packet = s.recv(BUFF_SIZE)
        # Appending information received from the server to data variable
        data += packet
        # If the length of the packet is less than the buffer size, it will break the While loop
        if len(packet) < BUFF_SIZE:
            break
    # Unserialising the information received from the server
    data = pickle.loads(data)
    # Returning the data received
    return data

# A function that performs AES Encryption Operation
# AES block size is 128 bits or 16 bytes
def AESEncrypt(plaintext, key, BLOCK_SIZE=16):
    # Generating AES Nonce
    # Maximum AES Nonce size is 96 bits or 12 bytes
    nonce = get_random_bytes(12)
    # Instantiating AES cipher
    # AES cipher using the key generated
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Encrypting data using AES cipher
    cipher_text_bytes = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    # Appending AES Nonce at the end of the encrypted data
    cipher_text_bytes = cipher_text_bytes + nonce
    # Returning AES Encrypted Data in bytes
    return cipher_text_bytes


# A function that performs AES Decryption Operation
# AES block size is 128 bits or 16 bytes
def AESDecrypt(cipher_text_bytes, key, BLOCK_SIZE=16):
    # Extracting AES Encrypted Data, 
    # Extracting AES Nonce
    cipher_text_bytes, nonce = cipher_text_bytes[:-12] , cipher_text_bytes[-12:]
    # Instantiating AES cipher with the same key and mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Decrypting data
    decrypted_text_bytes = unpad(cipher.decrypt(cipher_text_bytes), BLOCK_SIZE)
    # Returning AES Unencrypted Data in bytes
    return decrypted_text_bytes

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
    print(data)
    # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
    HMAC = hmac.new(HMACKey, data, digestmod="sha512")
    # If the HMAC generated matches to the value of HMAC received, the function will return True
    if HMAC == HMACReceived:
        return True
    # If the HMAC generated does not match to the value of HMAC received, the function will return False
    else:
        return False

# A function that performs AES Decryption Operation
def VerifierHMACDSIG(encryptedDataReceived, HMACReceived, serverDigest, serverPublicKey, serverSignature, clientDHPublicKey):
    
    data = encryptedDataReceived
    # A function that verifies the HMAC of the data received from server
    def HMACVerifier():
        # HMAC key is the same as the AES session key
        HMACKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
        # AES Encrypted Data received from Server
        # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
        HMAC = hmac.new(HMACKey, data, digestmod="sha512")
        # If the HMAC generated matches to the value of HMAC received, the function will return True
        if HMAC.hexdigest() == HMACReceived:
            return True
        # If the HMAC generated does not match to the value of HMAC received, the function will return False
        else:
            return False

    # A function that verifies the signature of the data received from server
    def digitalSignatureVerifier():
        from Cryptodome.Hash import SHA512
        # Verifying the signature of Data received from Server with the server public key of the RSA key pair
        verifier = pkcs1_15.new(RSA.import_key(serverPublicKey))
        digest = SHA512.new(data=data)
        if digest.digest() == serverDigest:
            try:
                # If the signaature is valid, the function will return True
                verifier.verify(digest, serverSignature)
                return True
            except:
                # If the signaature is not valid, the function will return False
                return False
        else: return False
    HMACResult = HMACVerifier()
    signatureResult = digitalSignatureVerifier()
    # If the HMAC verification and signature verification is successful, the codes below will execute
    if HMACResult and signatureResult:
        print("The HMAC and Digital Signature of the payload is verified!")
        return True
    # If the HMAC verification is not successful, the codes below will execute
    else:
        print(f"{redHighlight}Warning!{normalText} File content might be modified. Connection to server is terminated. Relaunch the program to get the menu again.")
        return False

# A function that extracts all the encrypted data from a data class called serverEncryptedPayload
def encryptedPayloadReceived(serverEncryptedPayload):
    # Instantiating the serverEncryptedPayload class to clientPayload variable
    clientPayload = clientEncryptedPayload(serverEncryptedPayload.encryptedFile, serverEncryptedPayload.HMAC, serverEncryptedPayload.digitalSignature, serverEncryptedPayload.clientPublicKey, serverEncryptedPayload.digest)
    # Returning the payload encrypted data received from the server
    return clientPayload.encryptedFile, clientPayload.HMAC, clientPayload.digest, clientPayload.clientPublicKey, clientPayload.digitalSignature

# A data class to store the encrypted day_end.csv, HMAC, digital signature of day_end.csv, client public key and digest
class clientEncryptedPayload:
    def __init__(self, encryptedFile, HMAC, digitalSignature, clientPublicKey, digest):
        self.encryptedFile = encryptedFile
        self.HMAC = HMAC
        self.digitalSignature = digitalSignature
        self.clientPublicKey = clientPublicKey
        self.digest = digest

# A function that stores all the encrypted data to a data class called clientEncryptedPayload
def encryptedPayloadSent(clientDHPublicKey, AESSessionKey):
    # AES Operation for files sent over the internet
    # A function that encrypts the client encrypted payload with server RSA public key

    with open(os.path.join(dirname, "menu_today.txt"), "rb+") as file:
        data = file.read()
        file.close()

    # A function that generates a HMAC-SHA512 of a file
    def HMACOperation():
        # HMAC key is the same as the AES session key
        HMACKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
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

    digitalSignature = digitalSignatureOperation()
    # Returning the payload encrypted data to be sent to the server
    # Instantiating the clientEncryptedPayload class to payload variable
    payload = clientEncryptedPayload(data, HMACOperation(), digitalSignature[2], (digitalSignature[1]).export_key(), (digitalSignature[0]).digest())
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
    # Receive request from client
    clientMessage = (receive_data(conn))
    # Receive data from client, CMD_GETMENU
    if clientMessage == sha256(cmd_GET_MENU.encode()).hexdigest(): 
        # Send menuPayload with 'clientRSAPublicKey', but it is actually server's generated public key. Same attribute type to make them recognizable in each other's program
        menuPayload = encryptedPayloadSent(clientDHPublicKey, AESSessionKey)
        send(menuPayload, conn)
        print(f"Client's ({addr[0]}:{addr[1]}) Menu of the day command has been received and its integrity verified. Sending encrypted menu to client!\n")
        conn.close()
    elif clientMessage == sha256(cmd_END_DAY.encode()).hexdigest():
        # Receving day_end.csv from server
        dataReceived = encryptedPayloadReceived(
            pickle.loads(AESDecrypt(receive_data(conn), AESSessionKey)))
        # Verifying data and storing it on server
        if VerifierHMACDSIG(dataReceived[0], dataReceived[1], dataReceived[2], dataReceived[3], dataReceived[4], clientDHPublicKey):
            filename = default_save_base +  "127.0.0.1" + "-" + now.strftime("%Y-%m-%d_%H%M")
            dest_file = open(os.path.join(dirname, "database/") + filename, "wb+")
            
            # If encrypted key file does not exist
            if not os.path.exists("database/key"):
                random_key = get_random_bytes(32)
                info_encrypted = AESEncrypt(dataReceived[0], random_key)
                dest_file.write(info_encrypted)
                encryptedKey = AESEncrypt(random_key, passwd)
                with open(os.path.join(dirname, "database/key"), 'wb+') as f:
                    f.write(encryptedKey)
                    f.close()
            # If it exists, decrypt it and get key to encrypt file
            else:
                key = open(os.path.join(dirname, "database/key"), 'rb+').read()
                decryptedKey = AESDecrypt(key, passwd)
                dest_file.write(AESEncrypt(dataReceived[0], decryptedKey))
                dest_file.close()
        else: conn.close()
    else: 
        print(f"The message from the client is invalid or has been tampered with. Closing connection from client {addr[0]}:{addr[1]}...")
        conn.close()
        
# Function to start the server
def start(passwd):
    server.listen()
    print(f"[LISTENING] SERVER IS LISTENING ON LOOPBACK ADDRESS")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handler, args=(conn, addr, passwd))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

# User Login Function
def user_login():
    # Function to prompt user for password and return hashed values
    def passwordInput():
        password_input= input("Please enter a password: ")
        passwd = sha256(password_input.encode('utf-8')).digest()
        password_input = sha256(password_input.encode('utf-8')).hexdigest()
        return password_input, passwd
    # Try to open file 
    if os.path.exists(os.path.join(dirname,"database/passwd.txt")):
        file = ((open(os.path.join(dirname,"database/passwd.txt"), "r+")).readline()).encode('utf-8')
        password_input, passwd = passwordInput()
        while True:
            if not bcrypt.checkpw(password_input.encode('utf-8'), file):
                print(f"{redHighlight}You have entered an invalid password{normalText}")
                password_input, passwd = passwordInput()
            else:
                print("Login Successful. Server Starting...")
                time.sleep(2)
                start(passwd)
            
    # If file does not exist, prompt user to create login
    else:
        # Creating new directory
        os.makedirs(os.path.join(dirname, "database"))
        print(f"-----Creation of Password-----\n[As this is your first time using the server, you will have to create a password which will be used for server-side encryption")
        password = input("Please enter a password: ")
        # Password must have more than 12 characters but lesser than 31, and must have a number. For the example, the password will be "passwordpassword1"
        while len(password) < 12 or len(password) > 30 or not any(map(lambda x: x.isnumeric(), [i for i in password])):
            password = input("Error. Please enter a valid password (More than 12 characters but less than 30. Must contain a number): ")
        else:
            # Creating of password and hashing with bcrypt with salt
            print("You have created a password. Please remember this password for future use of the server to access files.")
            with open(os.path.join(dirname,"database/passwd.txt"), "w+") as file:
                hashed = (sha256(password.encode('utf-8'))).hexdigest()
                passwd = sha256(password.encode('utf-8')).digest()
                hashed = bcrypt.hashpw(hashed.encode('utf-8'), bcrypt.gensalt())
                file.write(hashed.decode('utf-8'))
            time.sleep(2)
            # Start server and pass password as argument
            start(passwd)
# start(sha256('passwordpassword1'.encode('utf-8')).digest())
user_login()