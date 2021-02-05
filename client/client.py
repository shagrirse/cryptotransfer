# Note:
# Data sent or received to and from server not encrypted by RSA
# All client functions have been finalised

# Importing socket Module to perform socket operations
import socket
# Importing Random Module for generating random numbers
import random
# Importing Hashlib Module for hashing purposes
import hashlib
# Importing AES and RSA ciphers Module to perform AES and RSA mode of operations
from Cryptodome.Cipher import AES, PKCS1_OAEP
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
# Importing HMAC Module to perform HMAC operations
import hmac
# Importing base64 Module to perform base64 encoding or base64 decoding operations
import base64
# Importing Digital Signature Module to perfrom Digital Signature operations
from Cryptodome.Signature import pkcs1_15
# Importing RSA Module to perfrom RSA operations
from Cryptodome.PublicKey import RSA
# Importing pickle Module for serialising Python objects
import pickle
# Importing Diffie-Hellman Key Exchange to perform Diffle-Hellman Key Exchange operations
import pyDH

# Font Styles (Colours and Colour of Background)
# Red Bold Font with Red Background
redHighlight = "\x1b[1;37;41m"
# Default Font Styles
normalText = "\x1b[0;37;40m"

# Server's hostname or IP address
HOST = "127.0.0.1"
# The port used by the server
PORT = 8888
ADDRESS = (HOST,PORT)
# GET_MENU command
cmd_GET_MENU = b"GET_MENU"
# CLOSING command
cmd_END_DAY = b"CLOSING"

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(ADDRESS)
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

# A function that receives menu.txt file from server
def dataFromServer():
    # Sending GET_MENU command to the server
    send(cmd_GET_MENU, clientSocket)
    # Receiving information from the server
    data = receive_data(clientSocket)
    # Closing the connection between the server and the client
    clientSocket.close()
    # Indicating that the data has been sent to the server
    print(f"Length of data received from server: {len(data)}")
    # Returning the value received
    return data


# A function that sends day_end.csv file to server
def dataToServer(dataSent):
    # Sending CLOSING command to the server
    send(cmd_END_DAY, clientSocket)
    # Sending information to the server
    send(dataSent, clientSocket)
    # Indicating that the data has been sent to the server
    print(f"Length of data sent to server: {len(dataSent)}")


# A function that sends client public key to server to perform Diffle-Hellman Key Exchange
def clientDHPublicKeyToServer(clientDHPublicKey):
    # Sending information to the server
    send(clientDHPublicKey, clientSocket)
    # Indicating that the data has been sent to the server
    print(f"Length of data sent to server: {len(clientDHPublicKey)}")


# A function that receives server public key from server to perform Diffle-Hellman Key Exchange
def gettingDHServerPublicKey():
    # Receiving information from the server
    data = receive_data(clientSocket)
    # Indicating that the data has been sent to the server
    print(f"Length of data received from server: {len(data)}")
    # Returning the value received
    return data


# A function that performs Diffle-Hellman Key Exchange
def diffieHellmanKeyExchange():
    # Generating client public key
    clientDHPublicKey = pyDH.DiffieHellman(5).gen_public_key()
    # Returning the value of client public key
    return clientDHPublicKey


# A function that performs Diffle-Hellman Key Exchange Calculations
def diffieHellmanKeyExchangeCalculations(serverDHPublicKey):
    # Generating session key
    sessionKey = pyDH.DiffieHellman().gen_shared_key(serverDHPublicKey)
    # Hashing the session key to be a AES 256-bit session key
    AESSessionKey = hashlib.sha256(sessionKey.encode()).hexdigest()
    # Returning the value of AES Session Key
    return AESSessionKey


# A function that performs AES Encryption Operation
def AESOperation():
    with open("day_end.csv", "rb") as f:
        # Extracting data in bytes
        unencryptedData = f.read()
        # Generating AES Nonce
        # Maximum AES Nonce size is 96 bits or 12 bytes
        AESNonce = get_random_bytes(12)
        # Instantiating AES cipher
        AESCipher = AES.new(diffieHellmanKeyExchangeCalculations(
            serverDHPublicKey), AES.MODE_CTR, nonce=AESNonce)
        # AES block size is 128 bits or 16 bytes
        AESEncryptedData = AESCipher.encrypt(
            pad(unencryptedData, AES.block_size))
        # Appending AES Nonce at the end of the encrypted data
        AESEncryptedData = AESEncryptedData + AESNonce
        # Returning AES Encrypted Data in bytes
        return AESEncryptedData


# A function that generates a HMAC-SHA512 of a file
def HMACOperation():
    # HMAC key is the same as the AES session key
    HMACKey = diffieHellmanKeyExchangeCalculations(serverDHPublicKey)
    # AES Encrypted Data
    data = AESOperation()
    # Instantiating HMAC object and generating HMAC using SHA-512 hashing algorithm
    HMAC = hmac.new(HMACKey, data, digestmod="sha512")
    # Returning a HMAC-SHA512 in bytes
    return HMAC


# A function that signs a AES Encrypted Data
def digitalSignatureOperation():
    # Generating the key pair for client
    clientRSAKeyPair = RSA.generate(4096)
    # Extracting client public key from the generated key pair
    clientPublicKey = clientRSAKeyPair.publickey()
    # AES Encrypted Data
    data = AESOperation()
    # Generating SHA-512 digest of the AES encrypted data
    digest = hashlib.sha512(data.encode())
    # Signing the SHA-512 digest of the AES encrypted data with the private key of the RSA key pair
    signer = pkcs1_15.new(clientRSAKeyPair)
    signature = signer.sign(digest)
    # Returning the digest, client public key and digital signature of a AES Encrypted Data in bytes
    return digest, clientPublicKey, signature


# A data class to store the encrypted day_end.csv, HMAC, digital signature of day_end.csv, client public key and digest
class clientEncryptedPayload:
    def __init__(self):
        self.encryptedFile = ""
        self.HMAC = ""
        self.digitalSignature = ""
        self.clientPublicKey = b""
        self.digest = ""


# A function that stores all the encrypted data to a data class called clientEncryptedPayload
def encryptedPayloadSent():
    # Instantiating the clientEncryptedPayload class to payload variable
    payload = clientEncryptedPayload()
    # Assigning the value returned by AESOperation function to the class
    payload.encryptedFile = AESOperation()
    # Assigning the value returned by HMACOperation function to the class
    payload.HMAC = HMACOperation()
    # Assigning the value returned by digitalSignatureOperation function to the class
    payload.digitalSignature = digitalSignatureOperation()[2]
    # Assigning the value returned by digitalSignatureOperation function to the class
    payload.clientPublicKey = digitalSignatureOperation()[1]
    # Assigning the value returned by digitalSignatureOperation function to the class
    payload.digest = digitalSignatureOperation()[0]
    # Returning the payload encrypted data to be sent to the server
    return payload


# A function that extracts all the encrypted data from a data class called serverEncryptedPayload
def encryptedPayloadReceived(serverEncryptedPayload):
    # Instantiating the serverEncryptedPayload class to serverPayload variable
    serverPayload = serverEncryptedPayload()
    # Encrypted data from server
    encryptedDataReceived = serverPayload.encryptedFile
    # HMAC from server
    HMACReceived = serverPayload.HMAC
    # Server Digest
    serverDigest = serverPayload.digest
    # Server public key
    serverPublicKey = serverPayload.serverPublicKey
    # Server digital signature
    serverSignature = serverPayload.digitalSignature
    # Returning the payload encrypted data received from the server
    return encryptedDataReceived, HMACReceived, serverDigest, serverPublicKey, serverSignature


# A function that verifies the HMAC of the data received from server
def HMACVerifier(HMACReceived, encryptedDataReceived):
    # HMAC key is the same as the AES session key
    HMACKey = diffieHellmanKeyExchangeCalculations(serverDHPublicKey)
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


# A function that verifies the signature of the data received from server
def digitalSignatureVerifier(serverDigest, serverPublicKey, serverSignature):
    # Verifying the signature of AES Encrypted Data received from Server with the server public key of the RSA key pair
    verifier = pkcs1_15.new(serverPublicKey)
    try:
        # If the signaature is valid, the function will return True
        verifier.verify(serverDigest, serverSignature)
        return True
    except:
        # If the signaature is not valid, the function will return False
        return False


# A function that performs AES Decryption Operation
def AESDecryptionOperation(encryptedDataReceived, HMACReceived, serverDigest, serverPublicKey, serverSignature):
    # Verifying HMAC of content received
    HMACResult = HMACVerifier(HMACReceived, encryptedDataReceived)
    # Verifying signature of content received
    signatureResult = digitalSignatureVerifier(
        serverDigest, serverPublicKey, serverSignature)
    # If the HMAC verification and signature verification is successful, the codes below will execute
    if HMACResult == True and signatureResult == True:
        # Extracting AES Nonce
        AESNonce = encryptedDataReceived[-12:]
        # Extracting AES Encrypted Data
        AESEncryptedData = encryptedDataReceived[:-12]
        # Instantiating AES cipher
        AESCipher = AES.new(diffieHellmanKeyExchangeCalculations(
            serverDHPublicKey), AES.MODE_CTR, nonce=AESNonce)
        # AES block size is 128 bits or 16 bytes
        AESUnencryptedData = unpad(AESCipher.decrypt(
            AESEncryptedData), AES.block_size)
        with open("menu.csv", "wb") as f:
            # Writing menu content received from server to menu.csv file
            f.write(AESUnencryptedData)
    # If the HMAC verification is not successful, the codes below will execute
    else:
        print(f"{redHighlight}Warning!{normalText} File content might be modified. Decryption operation will not execute.")


# Transit Codes
# A function that generates client RSA key pair
def generateClientRSAKeyPair():
    # Generate 2048-bit long client RSA Key pair
    clientRSAKeyPair = RSA.generate(4096)
    # Extracting client RSA public key
    clientRSAPublicKey = clientRSAKeyPair.publickey().export_key()

    send(clientRSAPublicKey, clientSocket)
    # Indicating that the data has been sent to the server
    print("Client's RSA public key has been sent to the server!")

    # Returning client RSA private key
    return clientRSAKeyPair


# A function that receives Server RSA public key
def receiveServerRSAPublicKey():
    receivedServerPublicRSAKey = receive_data(clientSocket)
    # Indicating that the data has been received from the server
    print("Server's RSA public key has been received from the server!")
    receivedServerPublicRSAKey = RSA.import_key(receivedServerPublicRSAKey)
    # Return the server RSA public key
    return receivedServerPublicRSAKey


# A function that encrypts the client encrypted payload with server RSA public key
def encryptPayloadWithRSA(clientEncryptedPayload):
    # Getting the server RSA public key
    serverRSAPublicKey = sessionServerRSAPublicKey
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(serverRSAPublicKey)
    # Encrypting payload with server RSA public key
    clientRSAEncryptedPayload = RSACipher.encrypt(clientEncryptedPayload)
    # Returning RSA encrypted payload
    return clientRSAEncryptedPayload


# A function that decrypts the server encrypted payload received from server with client RSA private key
def decryptPayloadwithRSA(serverEncryptedPayload):
    # Getting the client RSA private key
    clientRSAPrivateKey = sessionClientRSAPrivateKey
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(clientRSAPrivateKey)
    # Decrypting payload with client RSA private key
    serverDecryptedPayload = RSACipher.decrypt(serverEncryptedPayload)
    # Returning decrypted payload
    return serverDecryptedPayload


# A function that encrypts client Diffle-Hellman public key
def encryptDiffieHellman(clientDHPublicKey):
    # Getting the server RSA public key
    serverRSAPublicKey = sessionServerRSAPublicKey
    # Instantiating RSA cipher
    RSACipher = PKCS1_OAEP.new(serverRSAPublicKey)
    # Encrypting client Diffle-Hellman public key with server RSA public key
    encryptedclientDHPublicKey = RSACipher.encrypt(str(clientDHPublicKey).encode())
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
    return decryptedServerDHPublicKey

try:
    # Main program
    # Getting client private key for decryption operations
    sessionClientRSAPrivateKey = generateClientRSAKeyPair()

    # Getting server public key for encryption operations
    sessionServerRSAPublicKey = receiveServerRSAPublicKey()

    # Getting server public key for Diffie-Hellman Key Exchange
    serverDHPublicKey = decryptDiffieHellman(gettingDHServerPublicKey())

    # Sending client public key to server to perform Diffle-Hellman Key Exchange
    clientDHPublicKeyToServer(encryptDiffieHellman(diffieHellmanKeyExchange()))

    # Receving menu.txt from server
    dataReceived = encryptedPayloadReceived(
        decryptPayloadwithRSA(dataFromServer()))

    # Decrypting encrypted menu.txt from server
    AESDecryptionOperation(
        dataReceived[0], dataReceived[1], dataReceived[2], dataReceived[3], dataReceived[4])

    # Sending day_end.csv file to server
    dataToServer(encryptPayloadWithRSA(encryptedPayloadSent()))
except:
    import traceback
    print(traceback.format_exc())

clientSocket.close()