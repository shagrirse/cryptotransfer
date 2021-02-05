#!/usr/bin/env python3

# Note:
# Data sent or received to and from server not encrypted by RSA
# All client functions have been finalised

# Importing socket Module to perform socket operations
import socket
# Importing Random Module for generating random numbers
import random
# Importing Hashlib Module for hashing purposes
import hashlib
# Importing AES Module to perform AES mode of operations
from Cryptodome.Cipher import AES
# Importing get_random_bytes to get random bytes suitable for cryptographic use
from Cryptodome.Random import get_random_bytes
# Importing Pad and Unpad Modules to perform pad and unpad operations
from Cryptodome.Util.Padding import pad, unpad
# Importing RSA module to perform RSA encryption
from Cryptodome.PublicKey import RSA
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
# GET_MENU command
cmd_GET_MENU = b"GET_MENU"
# CLOSING command
cmd_END_DAY = b"CLOSING"


# A function that receives menu.txt file from server
def dataFromServer():
    # Enabling the client socket to receive information from the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        # Enabling the client socket to contact the server using defined address and port number
        clientSocket.connect((HOST, PORT))
        # Sending GET_MENU command to the server
        clientSocket.sendall(cmd_GET_MENU)
        # Receiving information from the server
        data = clientSocket.recv(4096)
        # Unserialising the information received from the server
        dataReceived = pickle.loads(data)
        # Closing the connection between the server and the client
        clientSocket.close()
    # Indicating that the data has been sent to the server
    print(f"Length of data received from server: {len(data)}")
    # Closing the connection between the server and the client
    clientSocket.close()
    # Returning the value received
    return dataReceived


# A function that sends day_end.csv file to server
def dataToServer(dataSent):
    # Serialising the information to be sent to the server
    data = pickle.dumps(dataSent)
    # Enabling the client socket to send information to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        # Enabling the client socket to contact the server using defined address and port number
        clientSocket.connect((HOST, PORT))
        # Sending CLOSING command to the server
        clientSocket.sendall(cmd_END_DAY)
        # Sending information to the server
        clientSocket.sendall(data)
        # Closing the connection between the server and the client
        clientSocket.close()
    # Indicating that the data has been sent to the server
    print(f"Length of data sent to server: {len(data)}")
    # Closing the connection between the server and the client
    clientSocket.close()


# A function that sends client public key to server to perform Diffle-Hellman Key Exchange
def clientDHPublicKeyToServer(clientDHPublicKey):
    # Encoding UTF-8 to bytes
    data = clientDHPublicKey.encode()
    # Enabling the client socket to send information to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        # Enabling the client socket to contact the server using defined address and port number
        clientSocket.connect((HOST, PORT))
        # Sending information to the server
        clientSocket.sendall(data)
        # Closing the connection between the server and the client
        clientSocket.close()
    # Indicating that the data has been sent to the server
    print(f"Length of data sent to server: {len(data)}")
    # Closing the connection between the server and the client
    clientSocket.close()


# A function that receives server public key from server to perform Diffle-Hellman Key Exchange
def gettingDHServerPublicKey():
    # Enabling the client socket to receive information from the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        # Enabling the client socket to contact the server using defined address and port number
        clientSocket.connect((HOST, PORT))
        # Receiving information from the server
        data = clientSocket.recv(1024)
        # Decoding bytes to UTF-8
        dataReceived = data.decode()
        # Closing the connection between the server and the client
        clientSocket.close()
    # Indicating that the data has been sent to the server
    print(f"Length of data received from server: {len(data)}")
    # Closing the connection between the server and the client
    clientSocket.close()
    # Returning the value received
    return dataReceived


# A function that performs Diffle-Hellman Key Exchange
def diffieHellmanKeyExchange():
    # Generating client public key
    clientDHPublicKey = pyDH.DiffieHellman().gen_public_key()
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
        # Returning ASES Encrypted Data in bytes
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
    clientRSAKeyPair = RSA.generate(2048)
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


# Main program
# Getting server public key for Diffie-Hellman Key Exchange
serverDHPublicKey = gettingDHServerPublicKey()

# Sending client public key to server to perform Diffle-Hellman Key Exchange
clientDHPublicKeyToServer(diffieHellmanKeyExchange())

# Receving menu.txt from server
dataReceived = encryptedPayloadReceived(dataFromServer())

# Decrypting encrypted menu.txt from server
AESDecryptionOperation(
    dataReceived[0], dataReceived[1], dataReceived[2], dataReceived[3], dataReceived[4])

# Sending day_end.csv file to server
dataToServer(encryptedPayloadSent())

# Transit Codes
# Generate client RSA public key
def ClientRSAPublicKeygenerate():
    # Generate 2048-bit long RSA Key pair
    ClientPublicRSAKey = RSA.generate(2048).publickey()
    # Open file to write RSA key
    f = open('clientrsakey.pem','wb')
    # Write RSA key in the file
    f.write(key.export_key('PEM'))
    # Close the file
    f.close()
    # Return RSA key
    return ClientPublicRSAkey

# Open RSA public key generated from Server
def ServerRSAPublicKeyreceive():
    # Open file that contains the RSA key
    f = open('serverrsakey.pem', 'wb')
    # Import RSA key
    ServerRSAkey = RSA.import_key(f.read())
    # Return the RSA key
    return ServerPublicRSAkey

# Generate client RSA private key
def ClientRSAPrivateKeygenerate():
    # Generate 2048-bit long RSA Key pair
    ClientRSAkey = RSA.generate(2048)
    # Make RSA key generated a private key
    ClientPrivateRSAKey = ClientRSAkey.has_private()
    # Return RSA key
    return ClientPrivateRSAkey

# Encrypting the payload with SERVER RSA public key
def encryptPayloadWithRSA(payload):
    # To use the value of ClientPublicRSAKey in the function
    import ServerPublicRSAKey
    # Encrypt payload with server public key
    RSApayload = payload.encrypt(ServerPublicRSAKey)
    # Return encrypted payload
    return RSApayload

# Decrypting the payload received from server with Client RSA private key
def decryptPayloadwithRSA(serverEncryptedPayload):
    # To use the value of ClientPrivateRSAKey in the function
    import ClientPrivateRSAKey
    # Decrypt payload with client public key
    serverDecryptedPayload = serverEncryptedPayload.decrypt(ClientPrivateRSAKey)
    # Return decrypted payload
    return serverDecryptedPayload

# Encrypt Diffie Hellman Public Key
def encryptDiffie(clientDHPublicKey):
    # To use the value of ClientPublicRSAKey in the fucntion
    import ServerPublicRSAKey
    # Encrypt DH Public Key with Server RSA Public Key
    clientEncryptedDHPublicKey = clientDHPublicKey.encrypt(ServerPublicRSAKey)
    # Return Encrypted DH Public Key
    return clientEncryptedDHPublicKey