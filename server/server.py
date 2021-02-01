import datetime
import pickle
import time
import bcrypt
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import os
import random
import string

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "server\menu_today.txt"
default_save_base = "result-"
# Send function to send item to client
def send(message, s):
    msg = pickle.dumps(message)
    s.send(msg)
    
class clientEncryptedPayload:
    def __init__(self):
        self.encryptedFile = ""
        self.HMAC = ""
        self.digitalSignature = ""
        self.clientPublicKey = b""
        self.digest = ""

def AESEncrypt(text, key, BLOCK_SIZE = 16):
    non = get_random_bytes(12)
    if type(text) == bytes: text_in_bytes = text
    else: text_in_bytes = text.encode()
    cipher = AES.new(key, AES.MODE_CTR, nonce = non)
    cipher_text_bytes = cipher.encrypt(pad(text_in_bytes, BLOCK_SIZE))
    cipher_text_bytes = bytes(bytearray(cipher_text_bytes) + non)
    return cipher_text_bytes

def AESDecrypt(content_in_bytes, key, BLOCK_SIZE = 16):
    non = content_in_bytes[-12:]
    content_in_bytes = bytes(bytearray(content_in_bytes[:-12]))
    cipher = AES.new(key, AES.MODE_CTR, nonce = non)
    # Now decrypt the text using your new cipher
    decrypted_text_bytes = unpad(cipher.decrypt(content_in_bytes), BLOCK_SIZE)
    # Print the message in UTF8 (normal readable way
    decrypted_text = decrypted_text_bytes.decode()
    return decrypted_text

def process_connection( conn , ip_addr, passwd, MAX_BUFFER_SIZE):
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd: # ask for menu
                src_file = open(default_menu,"rb")
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b'':
                        break
                    send(read_bytes, conn)
                src_file.close()
                print("Processed SENDING menu")
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
                dest_file = open("server/database/" + filename,"wb")
                if not os.path.exists("server/database/key"):
                    key_file = open("server/database/key", "wb")
                    random_text = (''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k = 512))).encode('utf-8')
                    random_key = sha256(random_text).digest()
                    encryptedData = AESEncrypt(net_bytes[len(cmd_END_DAY):], random_key)
                    dest_file.write(encryptedData)
                    key_file.write(AESEncrypt(random_key, passwd.digest()))
                else:
                    key_file = AESDecrypt(open("server/database/key", "rb").readline(), passwd.digest())
                    encryptedData = AESEncrypt(net_bytes[len(cmd_END_DAY):], key_file)
                    dest_file.write(encryptedData)
                blk_count = blk_count + 1
        else:  # write other blocks
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    dest_file.close()
    print("Processed CLOSING done")


def client_thread(conn, ip, port, passwd, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, passwd, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + " ended")

def start_server(passwd):

    import socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')

    try:
        soc.bind(("127.0.0.1", 8888))
        print('Socket bind complete')
    except socket.error as msg:
        import sys
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket
    soc.listen(10)
    print('Socket now listening')

    # for handling task in separate jobs we need threading
    from threading import Thread

    # this will make an infinite loop needed for
    # not reseting server for every client
    while True:
        conn, addr = soc.accept()
        ip, port = str(addr[0]), str(addr[1])
        print('Accepting connection from ' + ip + ':' + port)
        try:
            Thread(target=client_thread, args=(conn, ip, port, passwd)).start()
        except:
            print("Terible error!")
            import traceback
            traceback.print_exc()
    soc.close()
    
def user_login():
    # Try to open file
    try:
        file = ((open("server/database/passwd.txt", "r")).readline()).encode('utf-8')
        password_input= input("Please enter a password: ")
        password_input = sha256(password_input.encode('utf-8')).hexdigest()
        passwd = sha256(password_input.encode('utf-8'))
        while True:
            if not bcrypt.checkpw(password_input.encode('utf-8'), file):
                password_input= input("Error.Please enter a password: ")
            else:
                print("Login Successful. Server Starting...")
                time.sleep(2)
                start_server(passwd)
            
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
            start_server(passwd)
        
user_login()

