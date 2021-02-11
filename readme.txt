Main Program Instructions:

1. Run 2 separate terminal (Mac or Linux) or Command Prompt / Windows PowerShell (Windows)
2. CD to the server directory (using terminal 1)
3. Type "python server.py"
4. CD to the client directory (using terminal 2)
5. Type "python client.py"

Viewing Day Closing File Content Instructions:

By program design, all day closing files stored in the database are encrypted using AES cipher.

To view the day day closing file content, follow these instructions:

1. Open a terminal (Mac or Linux) or Command Prompt / Windows PowerShell (Windows)
2. CD to the server directory
3. Type "python fileDecryption.py"

Notes:

1. You might like to start Wireshark to listen to the localhost (IP Address: 127.0.0.1) interface before running client.py.
2. Both server.py and client.py files require several third party Python packages to function properly. To install the appropriate libraries, open a terminal (Mac or Linux) or Command Prompt / Windows PowerShell (Windows) and type "pip install -r requirements.txt" with the working directory being the main folder.
3. By program design, the server is password protected. Please use the following password "passwordpassword1" to access the server.

File Directory Tree:

\ (Base Directory)
readme.txt
contributions.txt
requirements.txt
client (Sub-Directory)
server (Sub-Directory)

Client Sub-Directory Tree:
\ (client Sub-Directory)
client.py
day_end.csv
menu.png
style.qss
menu_today.txt (To be created after the client requests the menu from the server)

Server Sub-Directory Tree:
\ (server Sub-Directory)
fileDecryption.py
menu_today.txt
server.py
database (Sub-Directory to be created after launching the server for the first time)

Database Sub-Directory Tree:
\ (database Sub-Directory)
key (To be created after launching the server for the first time)
passwd.txt (To be created after launching the server for the first time)
result-<IP-Address>-<Year-Month-Date-Hour> (To be created after the server receives the day closing file from the client)