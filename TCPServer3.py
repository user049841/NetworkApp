
"""
Starter code from Wei Song/webcms
otherwise written by z5358863 Christopher Fam
"""
from socket import *
from threading import Thread, Lock
import os, sys, time
from datetime import datetime

# acquire server host and port from command line parameter
if len(sys.argv) != 3:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT NUM_CONSECUTIVE_FAILED_ATTEMPTS ======\n")
    exit(0)
if not sys.argv[2].isdecimal() or not (1 <= int(sys.argv[2]) <= 5):
    print(f"Invalid number of allowed failed consecutive attempt: {sys.argv[2]}. The valid value of"
            "argument number is an integer between 1 and 5")
    exit(0)

serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
max_fails = int(sys.argv[2])
serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(serverAddress)
COMMANDS = ["/msgto", "/activeuser", "/creategroup", "/joingroup", "/groupmsg", "/logout", "/p2pvideo"]


def get_time():
    current_time = datetime.now()
    formatted_time = current_time.strftime("%d %b %Y %H:%M:%S")
    return formatted_time


credentials = dict()
with open("credentials.txt", 'r') as file:
    for line in file:
        user, password = line.strip().split()
        # things that don't reset upon logout/exiting the client terminal.
        credentials[user] = {"password": password, "timer": 0, "fails": 0}

"""
    Define multi-thread class for client
    This class would be used to define the instance for each connection from each client
    For example, client-1 makes a connection request to the server, the server will call
    class (ClientThread) to define a thread for client-1, and when client-2 make a connection
    request to the server, the server will call class (ClientThread) again and create a thread
    for client-2. Each client will be running in a separate therad, which is the multi-threading
"""
class ClientThread(Thread):
    def __init__(self, clientAddress, clientSocket: socket):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False
        self.logged_in = False
        self.username = ""
        self.groups = set()
        self.joined_groups = set()
        self.client_udp_port = 0
        self.clientAlive = True
        
    def run(self):
        message = ''
        while self.clientAlive:
            if not self.logged_in:
                self.process_login()
                continue

            # use recv() to receive message from the client
            data = self.clientSocket.recv(1024)
            message = data.decode().strip()
            
            # if the message from client is empty, the client would be off-line then set the client as offline (alive=Flase)
            if message == '':
                continue
            
            if message.startswith("/msgto "):
                print(f"{self.username} issued a /msgto command")
                if len(message.split()) < 3:
                    message_to_send = "Usage: /msgto USERNAME MESSAGE_CONTENT"
                    self.clientSocket.send(message_to_send.encode())
                    continue
                self.process_msgto(message)
            
            if message == "/logout":
                self.process_logout()
                message_to_send = "Bye, " + self.username + "!"
                self.clientSocket.send(message_to_send.encode())
                self.clean_up()

            if message == "/activeuser":
                self.process_active_users()

            if message.startswith("/creategroup"):
                print(f"{self.username} issued a /creategroup command")
                if len(message.split()) < 3:
                    message = "Usage: /creategroup GROUPNAME USERNAME1 USERNAME2 ...\nMake sure "
                    message += "to enter a group name and at least 1 active user."
                    self.clientSocket.send(message.encode())
                    print("Return message: Group chat room is not created. Please enter at least one more active user")
                    continue
                self.process_create_group(message.strip())

            
            if message.startswith("/joingroup"):
                if len(message.split()) == 1 or len(message.split()) > 2:
                    message = "Usage: /joingroup GROUPNAME"
                    self.clientSocket.send(message.encode())
                    continue
                self.process_join_group(message.strip())

            if message.startswith("/groupmsg"):
                if len(message.split()) < 3:
                    message = "Usage: /joingroup GROUPNAME"
                    self.clientSocket.send(message.encode())
                    continue
                self.process_group_msg(message.strip())

            # handle invalid commands from the client
            if not any(message.startswith(i) for i in COMMANDS):
                message_to_send = "Error. Invalid command!"
                self.clientSocket.send(message_to_send.encode())
    
    """
        You can create more customized APIs here, e.g., logic for processing user authentication
        Each api can be used to handle one specific function, for example:
        def process_login(self):
            message = 'user credentials request'
            self.clientSocket.send(message.encode())
    """
    def process_login(self):
        data = self.clientSocket.recv(1024)
        message = data.decode()
        try:
            user, password = message.split()
        except:
            message_to_send = "Use a non-empty user and password"
            self.clientSocket.send(message_to_send.encode())
            return
        do_exit = False
        if user not in credentials:
            message_to_send = "Invalid password. Please try again"
        elif time.time() - credentials[user]["timer"] < 10:
            message_to_send = "Your account is blocked due to multiple login failures. Please try again later"
            do_exit = True
        elif credentials[user]["password"] != password:
            message_to_send = "Invalid password. Please try again"
            credentials[user]["fails"] += 1
            if credentials[user]["fails"] == max_fails:
                credentials[user]["fails"] = 0
                credentials[user]["timer"] = time.time()
                message_to_send = "Invalid Password. Your account has been blocked. Please try again later"
                do_exit = True
        else:
            credentials[user]["fails"] = 0
            message_to_send = "Welcome to Tessenger!"
            self.logged_in = True
            self.username = user
        
        self.clientSocket.send(message_to_send.encode())
        if self.logged_in:
            self.handle_login_success()
        if do_exit:
            self.clean_up()


    def handle_login_success(self):
        # get port
        data = self.clientSocket.recv(1024)
        message = data.decode()
        self.client_udp_port = int(message)

        # log details
        with userlog_lock:
            with open("userlog.txt", "a") as f:
                f.write(str(get_last_seq_number("userlog.txt")) + "; " + get_time() + "; " + 
                        self.username + "; " + self.clientAddress[0] + "; " + str(self.client_udp_port) + "\n")
        print(f"{self.username} is online")


    def process_logout(self):
        self.logged_in = False
        with userlog_lock:
            cur_num = 1
            with open("userlog.txt", "r") as f:
                lines = f.readlines()
            with open("userlog.txt", "w") as f:
                for line in lines:
                    if line.split(';')[2].strip() != self.username:
                        new_line = [str(cur_num)] + line.split('; ')[1:]
                        f.write("; ".join(new_line))
                        cur_num += 1
        print(f"{self.username} logout")


    def process_msgto(self, message):
        message = message[len("/msgto "):]
        found = False
        for client in all_threads:
            if client.username == message.split()[0]:
                time = get_time()
                content = message[len(client.username) + 1:]
                message_to_send = f"{time}, {self.username}: {content}"
                client.clientSocket.send(message_to_send.encode())
                message_to_send = "message sent at " + time + "."
                print(f"{self.username} message "
                      f"to {client.username} \"{content}\" at {time}.")
                self.clientSocket.send(message_to_send.encode())

                # add to messagelog.txt
                with messagelog_lock:
                    num = get_last_seq_number("messagelog.txt")
                    with open("messagelog.txt", "a") as f:
                        f.write(f"{str(num)}; {get_time()}; {client.username}; {content}")
                found = True
                break

        if not found:
            message_to_send = "User not online"
            self.clientSocket.send(message_to_send.encode())
            print(f"{self.username} attempted to send a message to the non-online user {message.split()[0]}")


    def process_active_users(self):
        users = []
        with userlog_lock:
            with open("userlog.txt", "r") as f:
                for line in f:
                    for thread in all_threads:
                        if thread.username in line and thread.username != self.username:
                            users.append(line.split('; '))
        users = [f"{i[2]}, {i[3]}, {i[4].strip()}, active since {i[1]}." for i in users]
        message = "\n".join(users)
        message = message or "No other active users."
        print(f"{self.username} issued /activeuser command.")
        print("Return Message:")
        print(message)
        self.clientSocket.send(message.encode())


    def process_create_group(self, message):
        message = message[len("/creategroup "):].strip()
        groupname = message[:message.index(" ")]
        users = message[len(groupname) + 1:].strip().split()
        if groupname in all_groups:
            message_to_send = f"Failed to create the group chat {groupname}: group name exists!"
            self.clientSocket.send(message_to_send.encode())
            print(f"Return message: Groupname {groupname} already exists.")
            return
        for user in users:
            user_client = next((thread for thread in all_threads if user == thread.username), None)
            if user_client is None:
                message = "All users in the create_group command must be active."
                self.clientSocket.send(message.encode())
                print("Return message: Group chat room is not created. Please enter only active users")
                return
        # Now we can add them to the group
        for user in users:
            user_client = next((thread for thread in all_threads if user == thread.username), None)
            user_client.groups.add(groupname)

        self.groups.add(groupname)
        self.joined_groups.add(groupname)
        message_to_send = f"Group chat created {groupname}"
        self.clientSocket.send(message_to_send.encode())
        all_groups.add(groupname)
        print(f"Return message: Group chat room has been created, room name: {groupname}, "
              f"users in this room: {', '.join(users + [self.username])}")
        with open(groupname + "_messagelog.txt", "w"): pass

        
    def process_join_group(self, message):
        groupname = message[len("/joingroup "):].strip()
        # Checks conditions - i.e. are they in the group but not joined, not in the group, etc.
        if groupname not in all_groups:
            print(f"{self.username} tried to join a group chat that doesn't exist.")
            message_to_send = f"Groupchat {groupname} doesn't exist."
            self.clientSocket.send(message_to_send.encode())
            return
        if groupname in self.joined_groups:
            print(f"Yoda tries to re-join to a group chat {groupname}")
            message_to_send = f"You have already joined groupchat {groupname}"
            self.clientSocket.send(message_to_send.encode())
            return
        if groupname not in self.groups:
            print(f"{self.username} tried to join a group chat that they can't access.")
            message_to_send = f"Groupchat {groupname} can't be accessed by you."
            self.clientSocket.send(message_to_send.encode())
            return
        self.joined_groups.add(groupname)
        users = ", ".join([client.username for client in all_threads if groupname in client.groups])
        print(f"Return message: Join group chat room successfully, " 
              f"room name: {groupname}, users in this room: {users}")
        message_to_send = f"Joined the group chat: {groupname} successfully."
        self.clientSocket.send(message_to_send.encode())

    
    def process_group_msg(self, message):
        message = message[len("/groupmsg "):].strip()
        groupname = message[:message.index(" ")]
        # Checks conditions - i.e. are they messaging a group that doesn't exist, etc.
        if groupname not in all_groups:
            message_to_send = "That group chat does not exist"
            print(f"{self.username} tried to message a group that does not exist")
            self.clientSocket.send(message_to_send.encode())
            return
        if groupname not in self.groups:
            message_to_send = "You are not in this group chat"
            print(f"{self.username} tried to message a group that they are not added to")
            self.clientSocket.send(message_to_send.encode())
            return
        if groupname not in self.joined_groups:
            message_to_send = "You are added but have not joined this group chat"
            print(f"{self.username} tried to message a group that they have not joined")
            self.clientSocket.send(message_to_send.encode())
            return
        content = message[len(groupname) + 1:].strip()
        message_to_send = f"{get_time()}, {groupname}, {self.username}: {content}"
        for client in all_threads:
            if groupname in client.joined_groups and client.clientAlive and client.username != self.username:
                client.clientSocket.send(message_to_send.encode())
        filename = groupname + "_messagelog.txt"
        with open(filename, "a") as f:
            num = get_last_seq_number(filename)
            f.write(f"{num}; {get_time()}; {self.username}; {content}\n")

        message_to_send = "Group chat message sent."
        self.clientSocket.send(message_to_send.encode())
        print(f"{self.username} issued a message in group chat {groupname}: {get_time()}; {self.username}; {content}")
        


    def clean_up(self):
        self.clientSocket.close()
        self.clientAlive = False
        exit(0)


# Returns the last sequence number in the userlog.txt/messagelog.txt file.
def get_last_seq_number(file_name):
    with open(file_name, "rb") as file:
        try:
            file.seek(-2, os.SEEK_END)
            while True:
                file.seek(-2, os.SEEK_CUR)
                if file.read(1) == b'\n':
                    break
        except OSError:
            file.seek(0)
        final = file.readline().decode()
        if final.strip() == "":
            last_num = 0
        else:
            last_num = int(final.strip().split()[0][0:-1])
    return last_num + 1




print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")

all_threads = []
all_groups = set()
userlog_lock = Lock()
messagelog_lock = Lock()
def code_to_run():
    with open("userlog.txt", "w"): pass
    with open("messagelog.txt", "w"): pass
    while True:
        serverSocket.listen()
        clientSockt, clientAddress = serverSocket.accept()
        clientThread = ClientThread(clientAddress, clientSockt)
        all_threads.append(clientThread)
        clientThread.start()

# Allows keyboard interrupts to work
new_thread = Thread(target=code_to_run)
new_thread.daemon = True
new_thread.start()
while True:
    time.sleep(0.3)
    # clean up inactive threads
    all_threads = [thread for thread in all_threads if thread.is_alive()]
