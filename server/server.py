# Importing datetime Module to concrete date and time related objects
import datetime
# Importing time Module to provide various functions to manipulate time values
import time
# Importing bcrypt Module to perform password hashing operations
import bcrypt
# Importing Hashlib Module for hashing purposes
from hashlib import sha256, sha512
# Importing os Module for paths
import os
# Importing threading Module to perform multithreading operations
import threading
# Importing socket Module to perform socket operations
import socket
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES, PKCS1_OAEP
# Importing get_random_bytes function to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad functions to perform pad and unpad operations
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
# Importing Cryptodome Hash Module for generating Digital Signatures
from Cryptodome.Hash import SHA512

# Font Styles (Colours and Colour of Background)
# Red Bold Font with Red Background
redHighlight = "\x1b[1;37;41m"
# Default Font Styles
normalText = "\x1b[0;37;40m"

# Defining relative path
dirname = os.path.dirname(__file__)
# Defining server's IP address and port number in the ADDRESS variable
ADDRESS = ("127.0.0.1", 8888)
# GET_MENU command
cmd_GET_MENU = "GET_MENU"
# CLOSING command
cmd_END_DAY = "CLOSING"
# Defining menu_today.txt file path
default_menu = "server/menu_today.txt"
# Defining file name format for receiving day_end.csv file from client
default_save_base = "result-"

# Enabling the server socket to send and receive information to and from the client
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Enabling the server socket to listen for client connections using defined address and port number
server.bind(ADDRESS)
# Initialising Diffie-Hellman keypair
DiffieHellmanKey = pyDH.DiffieHellman(5)


# A function that performs Diffle-Hellman Key Exchange
def diffieHellmanKeyExchange():
    # Generating server public key
    # The server public key is an integer
    serverDHPublicKey = DiffieHellmanKey.gen_public_key()
    # Returning the value of server public key
    return serverDHPublicKey


# A function that sends information to the client
def send(message, s):
    # Serialising the information to be sent to the client
    msg = pickle.dumps(message)
    # Sending information to the client
    s.send(msg)


# A function that receives information from the client
def receive_data(s):
    # Setting buffer size
    BUFF_SIZE = 8192
    # Initialising data variable as an empty byte string
    data = b''
    while True:
        # Receiving information from the client
        packet = s.recv(BUFF_SIZE)
        # Appending information received from the client to data variable
        data += packet
        # If the length of the packet is less than the buffer size, it will break the While loop
        if len(packet) < BUFF_SIZE:
            break
    # Unserialising the information received from the client
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
    cipher_text_bytes, nonce = cipher_text_bytes[:-12], cipher_text_bytes[-12:]
    # Instantiating AES cipher with the same key and mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Decrypting data
    decrypted_text_bytes = unpad(cipher.decrypt(cipher_text_bytes), BLOCK_SIZE)
    # Returning AES Unencrypted Data in bytes
    return decrypted_text_bytes


# Transit codes
# A function that receives client RSA public key
def ClientRSAPublicKeyreceive(conn):
    # Extracting client RSA public key
    receivedClientPublicRSAKey = RSA.import_key(receive_data(conn))
    # Returning the client RSA public key
    return receivedClientPublicRSAKey


# A function that generates server RSA key pair
def generateServerRSAKeyPair(conn):
    # Generate 4096-bit long server RSA Key pair
    serverRSAKeyPair = RSA.generate(4096)
    # Extracting server RSA public key
    serverRSAPublicKey = serverRSAKeyPair.publickey().export_key()
    # Sending information to the client
    send(serverRSAPublicKey, conn)
    # Returning server RSA private key
    return serverRSAKeyPair


# A function that decrypts the payload received from client with server RSA Private Key
def decryptPayloadwithRSA(clientEncryptedPayload, serverPrivateKey):
    # Decrypting payload with server private key
    clientDecryptedPayload = clientEncryptedPayload.decrypt(serverPrivateKey)
    # Returning the decrypted payload
    return clientDecryptedPayload


# A function that encrypts server Diffle-Hellman public key
def encryptDiffie(serverDHPublicKey, clientPublicRSA):
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(clientPublicRSA)
    # Encrypting server Diffle-Hellman public key with client RSA public key
    encryptedserverDHPublicKey = RSACipher.encrypt(
        str(serverDHPublicKey).encode())
    # Returning encrypted server Diffle-Hellman public key
    return encryptedserverDHPublicKey


# A function that decrypts client Diffie-Hellman public key
def decryptDiffieHellman(clientDHPublicKey, serverRSAPrivateKey):
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(serverRSAPrivateKey)
    # Decrypting client Diffle-Hellman public key with server RSA private key
    decryptedServerDHPublicKey = (RSACipher.decrypt(clientDHPublicKey))
    # Returning decrypted client Diffle-Hellman public key
    return decryptedServerDHPublicKey


# A function that performs Diffle-Hellman Key Exchange Calculations
def diffieHellmanKeyExchangeCalculations(clientDHPublicKey):
    # Generating session key
    sessionKey = DiffieHellmanKey.gen_shared_key(clientDHPublicKey)
    # Hashing the session key to be a AES 256-bit session key
    AESSessionKey = sha256(sessionKey.encode()).digest()
    # Returning the value of AES Session Key
    return AESSessionKey


# A function that verifies the HMAC and the Digital Signature of the content received
def VerifierHMACDSIG(encryptedDataReceived, HMACReceived, serverDigest, serverPublicKey, serverSignature, clientDHPublicKey):
    # AES Encrypted Data received from client
    data = encryptedDataReceived

    # A function that verifies the HMAC of the data received from client
    def HMACVerifier():
        # HMAC key is the same as the AES session key
        HMACKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
        # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
        HMAC = hmac.new(HMACKey, data, digestmod="sha512")
        # If the HMAC generated matches to the value of HMAC received, the function will return True
        if HMAC.hexdigest() == HMACReceived:
            return True
        # If the HMAC generated does not match to the value of HMAC received, the function will return False
        else:
            return False

    # A function that verifies the signature of the data received from client
    def digitalSignatureVerifier():
        from Cryptodome.Hash import SHA512
        # Verifying the signature of Data received from client with the client public key of the RSA key pair
        verifier = pkcs1_15.new(RSA.import_key(serverPublicKey))
        # Generating the digest of the data
        digest = SHA512.new(data=data)

        # Verifying if the generated digest is the same as the digest received
        if digest.digest() == serverDigest:
            try:
                # If the signaature is valid, the function will return True
                verifier.verify(digest, serverSignature)
                return True
            except:
                # If the signaature is not valid, the function will return False
                return False
        else:
            return False

    # Calling the HMACVerifier function to validate the HMAC
    HMACResult = HMACVerifier()

    # Calling the digitalSignatureVerifier function to validate the Digital Signature
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
    # Instantiating the clientEncryptedPayload class to clientPayload variable
    clientPayload = clientEncryptedPayload(serverEncryptedPayload.encryptedFile, serverEncryptedPayload.HMAC,
                                           serverEncryptedPayload.digitalSignature, serverEncryptedPayload.clientPublicKey, serverEncryptedPayload.digest)
    # Returning the payload encrypted data received from the client
    return clientPayload.encryptedFile, clientPayload.HMAC, clientPayload.digest, clientPayload.clientPublicKey, clientPayload.digitalSignature


# A data class to store the encrypted day_end.csv, HMAC, digital signature of day_end.csv, server public key and digest
class clientEncryptedPayload:
    def __init__(self, encryptedFile, HMAC, digitalSignature, clientPublicKey, digest):
        self.encryptedFile = encryptedFile
        self.HMAC = HMAC
        self.digitalSignature = digitalSignature
        self.clientPublicKey = clientPublicKey
        self.digest = digest


# A function that stores all the encrypted data to a data class called clientEncryptedPayload
def encryptedPayloadSent(clientDHPublicKey, AESSessionKey):
    # Instantiating file data as data variable
    with open(os.path.join(dirname, "menu_today.txt"), "rb+") as file:
        data = file.read()

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
        # Generating the key pair for server
        serverRSAKeyPair = RSA.generate(2048)
        # Extracting server public key from the generated key pair
        serverPublicKey = serverRSAKeyPair.publickey()
        # Generating SHA-512 digest of the AES encrypted data
        digest = SHA512.new(data=data)
        # Signing the SHA-512 digest of the AES encrypted data with the private key of the RSA key pair
        signer = pkcs1_15.new(serverRSAKeyPair)
        signature = signer.sign(digest)
        # Returning the digest, server public key and digital signature of a AES Encrypted Data in bytes
        return digest, serverPublicKey, signature

    # Getting the digital signature of the menu_today.txt file
    digitalSignature = digitalSignatureOperation()

    # Returning the payload encrypted data to be sent to the client
    # Instantiating the clientEncryptedPayload class to payload variable
    payload = clientEncryptedPayload(data, HMACOperation(
    ), digitalSignature[2], (digitalSignature[1]).export_key(), (digitalSignature[0]).digest())

    # Returning the encrypted pickled payload and AES session key
    return AESEncrypt(pickle.dumps(payload), AESSessionKey)


# A function that handles client connections
def handler(conn, addr, passwd):
    # Getting the current date and time
    now = datetime.datetime.now()
    # Getting the server RSA private key
    sessionServerRSAPrivateKey = generateServerRSAKeyPair(conn)
    # Indicating that the server has generated its RSA public key and sent its RSA public key to the client
    time.sleep(2)
    print(
        f"Server's RSA public key has been generated and sent to the client {addr[0]}:{addr[1]}\n")
    sessionClientRSAPublicKey = ClientRSAPublicKeyreceive(conn)
    # Indicating that the data has been received from the client
    print(
        f"Client's Public RSA key (Client {addr[0]}:{addr[1]}) has been received!\n")
    # Sending the encrypted server's Diffie-Hellman public key to the client, encrypted with the client's RSA public key
    serverDHPublicKey = encryptDiffie(
        diffieHellmanKeyExchange(), sessionClientRSAPublicKey)
    send(serverDHPublicKey, conn)
    print(
        f"Diffie Hellman key has been generated and sent to the client (Client {addr[0]}:{addr[1]})\n")
    # Receiving client's Diffie-Hellman public key and decrypt it with server's RSA private key
    clientEncryptedDHPublicKey = receive_data(conn)
    clientDHPublicKey = int((decryptDiffieHellman(
        clientEncryptedDHPublicKey, sessionServerRSAPrivateKey)))
    # Getting the AES session key
    AESSessionKey = diffieHellmanKeyExchangeCalculations(clientDHPublicKey)
    # Indicating that the data has been received from the client
    print(
        f"Client's ({addr[0]}:{addr[1]}) Diffie Hellman public key has been received!\n")
    # Receiving request from the client
    clientMessage = (receive_data(conn))
    # Receiving GET_MENU command from the client
    if clientMessage == sha256(cmd_GET_MENU.encode()).hexdigest():
        # Instantiating the menuPayload with clientDHPublicKey as the parameter for generating the AES session key
        menuPayload = encryptedPayloadSent(clientDHPublicKey, AESSessionKey)
        # Sending the menuPayload to the client
        send(menuPayload, conn)
        # Indicating that the data has been sent to the client
        print(
            f"Client's ({addr[0]}:{addr[1]}) Menu of the day command has been received and its integrity verified. Sending encrypted menu to client!\n")
        # Closing the connection between the server and the client
        conn.close()
    # Receiving CLOSING command from the client
    elif clientMessage == sha256(cmd_END_DAY.encode()).hexdigest():
        # Receving day_end.csv file from the client
        dataReceived = encryptedPayloadReceived(
            pickle.loads(AESDecrypt(receive_data(conn), AESSessionKey)))
        # Verifying data and storing it on the server
        if VerifierHMACDSIG(dataReceived[0], dataReceived[1], dataReceived[2], dataReceived[3], dataReceived[4], clientDHPublicKey):
            # Renaming the file received to the appropriate file naming convention
            filename = default_save_base + "127.0.0.1" + \
                "-" + now.strftime("%Y-%m-%d_%H%M")
            # Saving the file received to the correct file path
            dest_file = open(os.path.join(
                dirname, "database/") + filename, "wb+")

            # If the encrypted key file does not exist, the codes below will execute
            if not os.path.exists("database/key"):
                # Generating a random 32-byte key
                random_key = get_random_bytes(32)
                # Encrypting the file content with the random 32-byte key using AES encryption
                info_encrypted = AESEncrypt(dataReceived[0], random_key)
                # Writing the encrypted file content to the destination file
                dest_file.write(info_encrypted)
                # Encrypting the random 32-byte key with the user's password
                encryptedKey = AESEncrypt(random_key, passwd)
                # Saving the encrypted key to a file
                with open(os.path.join(dirname, "database/key"), 'wb+') as f:
                    f.write(encryptedKey)
            # If the encrypted key file exists, the codes below will execute
            else:
                # Getting the encrypted random 32-byte key
                key = open(os.path.join(dirname, "database/key"), 'rb+').read()
                # Decrypting the random 32-byte key using the user's password
                decryptedKey = AESDecrypt(key, passwd)
                # Encrypting the file content with the random 32-byte key using AES encryption
                dest_file.write(AESEncrypt(dataReceived[0], decryptedKey))
                # Closing the destination file
                dest_file.close()
        else:
            # Closing the connection between the server and the client
            conn.close()
    else:
        # Indicating that the data received from the client has been tampered with
        print(
            f"The message from the client is invalid or has been tampered with. Closing connection from client {addr[0]}:{addr[1]}...")
        # Closing the connection between the server and the client
        conn.close()


# A function that starts the server
def start(passwd):
    # Getting the server to listen for incoming client connections
    server.listen()
    # Indicating that the server is listening for incoming client connections
    print(f"[LISTENING] SERVER IS LISTENING ON LOOPBACK ADDRESS")
    while True:
        # Accept any incoming client connections
        conn, addr = server.accept()
        # Initialising a new thread
        thread = threading.Thread(target=handler, args=(conn, addr, passwd))
        # Start the new thread
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


# A function that handles the user login
def user_login():
    # A function that prompts the user for a password and returns the hashed values
    def passwordInput():
        # Getting a password input from the user
        password_input = input("Please enter a password: ")
        # Hashing the password input with SHA-256
        passwd = sha256(password_input.encode('utf-8')).digest()
        password_input = sha256(password_input.encode('utf-8')).hexdigest()
        # Returning the hashed password input
        return password_input, passwd
    # Trying to open file
    if os.path.exists(os.path.join(dirname, "database/passwd.txt")):
        file = ((open(os.path.join(dirname, "database/passwd.txt"), "r+")
                 ).readline()).encode('utf-8')
        password_input, passwd = passwordInput()
        while True:
            # If the user has entered an invalid password, the codes below will execute
            if not bcrypt.checkpw(password_input.encode('utf-8'), file):
                print(
                    f"{redHighlight}You have entered an invalid password{normalText}")
                password_input, passwd = passwordInput()
            # If the user has entered a valid password, the codes below will execute
            else:
                print("Login Successful. Server Starting...")
                time.sleep(2)
                # Starting the server and passing the password as an argument
                start(passwd)

    # If file does not exist, the server will prompt the user to create a new password
    else:
        # Creating a new database directory
        os.makedirs(os.path.join(dirname, "database"))
        # Indicating to the user that he or she is creating the password
        print(
            f"-----Creation of Password-----\n[As this is your first time using the server, you will have to create a password which will be used for server-side encryption")
        # Getting a password input from the user
        password = input("Please enter a password: ")
        # The password must have more than 12 characters but lesser than 31, and must have a number
        while len(password) < 12 or len(password) > 30 or not any(map(lambda x: x.isnumeric(), [i for i in password])):
            password = input(
                "Error. Please enter a valid password (More than 12 characters but less than 30. Must contain a number): ")
        else:
            # Creating the password and hashing with bcrypt with salt
            print("You have created a password. Please remember this password for future use of the server to access files.")
            with open(os.path.join(dirname, "database/passwd.txt"), "w+") as file:
                hashed = (sha256(password.encode('utf-8'))).hexdigest()
                passwd = sha256(password.encode('utf-8')).digest()
                hashed = bcrypt.hashpw(
                    hashed.encode('utf-8'), bcrypt.gensalt())
                file.write(hashed.decode('utf-8'))
            time.sleep(2)
            # Starting the server and passing the password as an argument
            start(passwd)


# Calling the user_login function to initiate user login authentication on the server
user_login()
