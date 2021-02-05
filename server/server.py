import datetime
import pickle
import time
import bcrypt
from hashlib import sha256
from Cryptodome.Cipher import AES
# Importing RSA module to perform RSA encryption
from Cryptordome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import os
import socket
import threading
import pyDH

SERVER_IP = socket.gethostbyname(socket.gethostname()) # Get IP address from current machine
ADDRESS = (SERVER_IP, 8888) # Store server IP and port number in the 'ADDRESS' variable
DC_MSG = "!DISCONNECT FROM SERVER!" # Disconnect message sent from client to server to drop session
cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "server\menu_today.txt"
default_save_base = "result-"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)

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

def handler(conn, addr, passwd):
    now = datetime.datetime.now()
    while True:
        try:
            message = receive_data(conn)
            if type(message) == pyDH.DiffieHellman:
                # TODO: Generate DH public key and send to client
            elif cmd_GET_MENU in message: # ask for menu
                src_file = open(default_menu,"rb")
                # TODO: Encryption
                conn.send(src_file)
                src_file.close()
            elif type(message) == clientEncryptedPayload:
                filename = default_save_base +  addr[0] + "-" + now.strftime("%Y-%m-%d_%H%M")
                dest_file = open("server/database/" + filename,"wb")
                print("lol")
                if not os.path.exists("server/database/key"):
                    random_key = get_random_bytes(32)
                    info_encrypted = AESEncrypt(message, random_key)
                    dest_file.write(info_encrypted)
                else:
                    print()
            break
        except Exception as e:
            print(e)
            break

def start(passwd):
    server.listen()
    print(f"[LISTENING] SERVER IS LISTENING ON {SERVER_IP}")
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

# Transit codes
# Generate server RSA public key
def ServerRSAPublicKeygenerate():
    # Generate 2048-bit long RSA Key pair
    ServerRSAkey = RSA.generate(2048)
    # Open file to write RSA key
    f = open('serverrsakey.pem','wb')
    # Write RSA key in the file
    f.write(key.export_key('PEM'))
    # Close the file
    f.close()
    # Return RSA key
    return ServerPublicRSAkey

# Open RSA public key generated from Client
def ClientRSAPublicKeyreceive():
    # Open file that contains the RSA key
    f = open('clientrsakey.pem', 'wb')
    # Import RSA key
    ClientRSAkey = RSA.import_key(f.read())
    # Return the RSA key
    return ClientPublicRSAkey

# Generate client RSA private key
def ServerRSAPrivateKeygenerate():
    # Generate 2048-bit long RSA Key pair
    ServerRSAkey = RSA.generate(2048)
    # Make RSA key generated a private key
    ServerPrivateRSAKey = ServerRSAkey.has_private()
    # Return RSA key
    return ServerPrivateRSAkey