# Importing socket Module to perform socket operations
import socket
# Importing Hashlib Module for hashing purposes
from hashlib import sha256, sha512
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES, PKCS1_OAEP
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
# Importing HMAC Module to perform HMAC operations
import hmac
# Importing Digital Signature Module to perfrom Digital Signature operations
from Cryptodome.Signature import pkcs1_15
# Importing RSA Module to perfrom RSA operations
from Cryptodome.PublicKey import RSA
# Importing pickle Module for serialising Python objects
import pickle
# Importing Diffie-Hellman Key Exchange to perform Diffle-Hellman Key Exchange operations
import pyDH
# Importing Cryptodome Hash Module for generating Digital Signatures
from Cryptodome.Hash import SHA512

# Font Styles (Colours and Colour of Background)
# Red Bold Font with Red Background
redHighlight = "\x1b[1;37;41m"
# Default Font Styles
normalText = "\x1b[0;37;40m"

# Server's hostname or IP address
HOST = "127.0.0.1"
# The port used by the server
PORT = 8888
# Address that contains server's hostname or IP address and port used by the server
ADDRESS = (HOST, PORT)
# GET_MENU command
cmd_GET_MENU = b"GET_MENU"
# CLOSING command
cmd_END_DAY = b"CLOSING"

# Enabling the client socket to send and receive information to and from the server
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Enabling the client socket to contact the server using defined address and port number
clientSocket.connect(ADDRESS)
# Initialising Diffie-Hellman keypair
DiffieHellmanKey = pyDH.DiffieHellman(5)


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
    # Extracting AES Encrypted Data
    cipher_text_bytes = cipher_text_bytes[:-12]
    # Extracting AES Nonce
    nonce = cipher_text_bytes[-12:]
    # Instantiating AES cipher with the same key and mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Decrypting data
    decrypted_text_bytes = unpad(cipher.decrypt(cipher_text_bytes), BLOCK_SIZE)
    # Returning AES Unencrypted Data in bytes
    return decrypted_text_bytes


# A function that receives menu.txt file from the server
def dataFromServer():
    # Sending the hashed GET_MENU command to the server
    send((sha256(cmd_GET_MENU)).hexdigest(), clientSocket)
    # Receiving information from the server
    data = receive_data(clientSocket)
    # Indicating that the data has been received from the server
    print("The encrypted menu has been received from the server.")
    # Returning the data received
    return data


# A function that sends day_end.csv file to the server
def dataToServer(dataSent):
    # Sending the hashed CLOSING command to the server
    send(sha256(cmd_END_DAY).hexdigest(), clientSocket)
    # Sending information to the server
    send(dataSent, clientSocket)
    # Indicating that the data has been sent to the server
    print("The encrypted day_end.csv file has been sent to the server.")


# A function that sends client public key to the server to perform Diffle-Hellman Key Exchange
def clientDHPublicKeyToServer(clientDHPublicKey):
    # Sending information to the server
    send(clientDHPublicKey, clientSocket)
    # Indicating that the data has been sent to the server
    print("The encrypted client's Diffie-Hellman public key has been sent to the server.")


# A function that receives server public key from server to perform Diffle-Hellman Key Exchange
def gettingDHServerPublicKey():
    # Receiving information from the server
    data = receive_data(clientSocket)
    # Indicating that the data has been received from the server
    print("The encrypted server's Diffie-Hellman public key has been received from the server.")
    # Returning the data received
    return data


# A function that performs Diffle-Hellman Key Exchange
def diffieHellmanKeyExchange():
    # Generating client public key
    # The client public key is an integer
    clientDHPublicKey = DiffieHellmanKey.gen_public_key()
    # Returning the value of client public key
    return clientDHPublicKey


# A function that performs Diffle-Hellman Key Exchange Calculations
def diffieHellmanKeyExchangeCalculations(serverDHPublicKey):
    # Generating session key
    sessionKey = DiffieHellmanKey.gen_shared_key(serverDHPublicKey)
    # Hashing the session key to be a AES 256-bit session key
    AESSessionKey = sha256(sessionKey.encode()).digest()
    # Returning the value of AES Session Key
    return AESSessionKey


# A data class to store the encrypted day_end.csv, HMAC, digital signature of day_end.csv, client public key and digest
class clientEncryptedPayload:
    def __init__(self, encryptedFile, HMAC, digitalSignature, clientPublicKey, digest):
        self.encryptedFile = encryptedFile
        self.HMAC = HMAC
        self.digitalSignature = digitalSignature
        self.clientPublicKey = clientPublicKey
        self.digest = digest


# A function that stores all the encrypted data to a data class called clientEncryptedPayload
def encryptedPayloadSent(AESSessionKey):
    # Instantiating file data as data variable
    with open("day_end.csv", "rb") as file:
        # Reading file data from day_end.csv file as bytes
        data = file.read()

    # A function that generates a HMAC-SHA512 of a file

    def HMACOperation():
        # HMAC key is the same as the AES session key
        HMACKey = diffieHellmanKeyExchangeCalculations(serverDHPublicKey)
        # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
        HMAC = hmac.new(HMACKey, data, digestmod="sha512")
        # Returning a HMAC-SHA512 in bytes
        return HMAC.hexdigest()

    # A function that signs a AES Encrypted Data

    def digitalSignatureOperation():
        # Generating the key pair for client
        clientRSAKeyPair = RSA.generate(2048)
        # Extracting client public key from the generated key pair
        clientPublicKey = clientRSAKeyPair.publickey()
        # Generating SHA-512 digest of the AES encrypted data
        digest = SHA512.new(data=data)
        # Signing the SHA-512 digest of the AES encrypted data with the private key of the RSA key pair
        signer = pkcs1_15.new(clientRSAKeyPair)
        signature = signer.sign(digest)
        # Returning the digest, client public key and digital signature of a AES Encrypted Data in bytes
        return digest, clientPublicKey, signature

    # Getting the digital signature of the day_end.csv file
    digitalSignature = digitalSignatureOperation()

    # Getting the payload of encrypted data to be sent to the server
    # Instantiating the clientEncryptedPayload class to payload variable
    payload = clientEncryptedPayload(data, HMACOperation(
    ), digitalSignature[2], (digitalSignature[1]).export_key(), (digitalSignature[0]).digest())

    # Returning the encrypted pickled payload and AES session key
    return AESEncrypt(pickle.dumps(payload), AESSessionKey)


# A function that extracts all the encrypted data from a data class called serverEncryptedPayload
def encryptedPayloadReceived(serverEncryptedPayload):
    # Instantiating the serverEncryptedPayload class to serverPayload variable
    serverPayload = clientEncryptedPayload(serverEncryptedPayload.encryptedFile, serverEncryptedPayload.HMAC,
                                           serverEncryptedPayload.digitalSignature, serverEncryptedPayload.clientPublicKey, serverEncryptedPayload.digest)
    # Returning the payload encrypted data received from the server
    return serverPayload.encryptedFile, serverPayload.HMAC, serverPayload.digest, serverPayload.clientPublicKey, serverPayload.digitalSignature


# A function that verifies the HMAC and the Digital Signature of the content received
def HMAC_DS_Verifier(encryptedDataReceived, HMACReceived, serverDigest, serverPublicKey, serverSignature):
    # Drcrypted Server Payload
    data = encryptedDataReceived

    # A function that verifies the HMAC of the data received from server

    def HMACVerifier():
        # HMAC key is the same as the AES session key
        HMACKey = diffieHellmanKeyExchangeCalculations(serverDHPublicKey)
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
        # Verifying the signature of data received from Server with the server public key of the RSA key pair
        verifier = pkcs1_15.new(RSA.import_key(serverPublicKey))
        # Generating the digest of the data
        digest = SHA512.new(data=data)

        # Verifying if the generated digest is the same as the digest received
        if digest.digest() == serverDigest:
            try:
                # If the signature is valid, the function will return True
                verifier.verify(digest, serverSignature)
                return True
            except:
                # If the signature is not valid, the function will return False
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
        # Writing data to the file as plaintext
        with open("menu_today.txt", "w") as f:
            f.write(encryptedDataReceived.decode())
    # If the HMAC verification is not successful, the codes below will execute
    else:
        print(f"{redHighlight}Warning!{normalText} File content might be modified. Connection to server is terminated. Relaunch the program to get the menu again.")
        clientSocket.close()


# Transit Codes
# A function that generates client RSA key pair
def generateClientRSAKeyPair():
    # Generate 4096-bit long client RSA Key pair
    clientRSAKeyPair = RSA.generate(4096)
    # Extracting client RSA public key
    clientRSAPublicKey = clientRSAKeyPair.publickey().export_key()
    # Sending information to the server
    send(clientRSAPublicKey, clientSocket)
    # Indicating that the data has been sent to the server
    print("Client's RSA public key has been sent to the server!")
    # Returning client RSA private key
    return clientRSAKeyPair


# A function that receives Server RSA public key
def receiveServerRSAPublicKey():
    # Receiving information from the server
    receivedServerPublicRSAKey = receive_data(clientSocket)
    # Indicating that the data has been received from the server
    print("Server's RSA public key has been received from the server!")
    # # Extracting server RSA public key
    receivedServerPublicRSAKey = RSA.import_key(receivedServerPublicRSAKey)
    # Return the server RSA public key
    return receivedServerPublicRSAKey


# A function that encrypts client Diffle-Hellman public key
def encryptDiffieHellman(clientDHPublicKey):
    # Getting the server RSA public key
    serverRSAPublicKey = sessionServerRSAPublicKey
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(serverRSAPublicKey)
    # Encrypting client Diffle-Hellman public key with server RSA public key
    encryptedclientDHPublicKey = RSACipher.encrypt(
        str(clientDHPublicKey).encode())
    # Returning encrypted client Diffle-Hellman public key
    return encryptedclientDHPublicKey


# A function that decrypts server Diffie-Hellman public key
def decryptDiffieHellman(serverDHPublicKey):
    # Getting the client RSA private key
    clientRSAPrivateKey = sessionClientRSAPrivateKey
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(clientRSAPrivateKey)
    # Decrypting server Diffle-Hellman public key with client RSA private key
    decryptedServerDHPublicKey = RSACipher.decrypt(serverDHPublicKey)
    # Returning decrypted client Diffle-Hellman public key
    return int(decryptedServerDHPublicKey)


# Main program
# Getting client private key for decryption operations
sessionClientRSAPrivateKey = generateClientRSAKeyPair()

# Getting server public key for encryption operations
sessionServerRSAPublicKey = receiveServerRSAPublicKey()

# Getting server public key for Diffie-Hellman Key Exchange
serverEncryptedDHPublicKey = gettingDHServerPublicKey()
serverDHPublicKey = decryptDiffieHellman(serverEncryptedDHPublicKey)

# Sending client public key to server to perform Diffle-Hellman Key Exchange
clientDHPublicKey = encryptDiffieHellman(diffieHellmanKeyExchange())
clientDHPublicKeyToServer(clientDHPublicKey)

# Getting AES Session Key
AESSessionKey = diffieHellmanKeyExchangeCalculations(serverDHPublicKey)

# Receving menu.txt from the server
dataReceived = encryptedPayloadReceived(
    pickle.loads(AESDecrypt(dataFromServer(), AESSessionKey)))

# Decrypting encrypted menu.txt from server
HMAC_DS_Verifier(
    dataReceived[0], dataReceived[1], dataReceived[2], dataReceived[3], dataReceived[4])

# Sending day_end.csv file to server
dataToServer(encryptedPayloadSent(AESSessionKey))

# Closing the connection between the server and the client
clientSocket.close()
