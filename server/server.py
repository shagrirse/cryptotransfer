import datetime

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"
aushdgasuiodguia
def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):
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
                    conn.send(read_bytes)
                src_file.close()
                print("Processed SENDING menu")
                return
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
                dest_file = open(filename,"wb")
                dest_file.write( net_bytes[ len(cmd_END_DAY): ] )  # remove the CLOSING header
                blk_count = blk_count + 1
        else:  # write other blocks
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    dest_file.close()
    print("Processed CLOSING done")


def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + " ended")

def start_server():

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
            Thread(target=client_thread, args=(conn, ip, port)).start()
        except:
            print("Terible error!")
            import traceback
            traceback.print_exc()
    soc.close()

start_server()
