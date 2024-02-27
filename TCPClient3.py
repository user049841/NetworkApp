"""
Starter code comes from Wei Song/webcms
otherwise written by z5358863 Christopher Fam
"""
from socket import *
import sys
import threading
import time
import os

#Server would be running on the same host as Client
if len(sys.argv) != 4:
    print("\n===== Error usage, python3 TCPClient3.py SERVER_IP SERVER_PORT CLIENT_UDP_SERVER_PORT ======\n")
    exit(0)
serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
# listen to udp traffic here
client_udp_port = int(sys.argv[3])
serverAddress = (serverHost, serverPort)


def code_to_run():
    # define a socket for the client side, it would be used to communicate with the server
    clientSocket = socket(AF_INET, SOCK_STREAM)

    stop_event.clear()
    receiving_thread = threading.Thread(target=receive_msg, args=(clientSocket,))
    receiving_thread.start()


    # build connection with the server and send message to it
    clientSocket.connect(serverAddress)
    logged_in = False
    print("Please login")
    # keys are the usernames, values are  (ip addresses, udp_port).
    cur_online = dict()
    while True:
        if not logged_in:
            user = input("Username: ")
            password = input("Password: ")
            message = user + " " + password
            clientSocket.sendall(message.encode())
            data = clientSocket.recv(1024)
            received_message = data.decode()
            print(received_message)
            if received_message == "Welcome to Tessenger!":
                logged_in = True
                message = str(client_udp_port)
                clientSocket.sendall(message.encode())
            if (received_message == "Invalid Password. Your account has been blocked. Please try again later" or
                received_message == "Your account is blocked due to multiple login failures. Please try again later"):
                exit(0)
            continue
            
        print("Enter one of the following commands (/msgto, /activeuser, /creategroup, "
                        "/joingroup, /groupmsg, /p2pvideo, /logout: ")
        
        # Handles receiving messages whilst allowing the user to send input.
        # Note that we need to (un)pause the thread, meaning that we have to check at
        # some point if the stop_event is set. In order to do this, we need to temporarily
        # disable blocking so that the program can repeatedly check this.
        stop_event.set()
        clientSocket.setblocking(False)
        message = input()
        stop_event.clear()
        is_stopped.wait()
        clientSocket.setblocking(True)

        # If we are doing p2pvideo, we don't want to send the message to the server
        if message.startswith("/p2pvideo"):
            if len(message.split()) != 3:
                print("Usage: /p2pvideo username filename")
                continue
            udp_sender_thread = threading.Thread(target=udp_sender, args=(message, cur_online))
            udp_sender_thread.daemon = True
            udp_sender_thread.start()
            continue


        clientSocket.sendall(message.encode())
        # receive response from the server
        # 1024 is a suggested packet size, you can specify it as 2048 or others
        data = clientSocket.recv(1024)
        received_message = data.decode()
        print(received_message)
        if message == "/activeuser":
            cur_online.clear()
            if received_message.startswith("No other"):
                continue
            users = received_message.split('\n')
            for user in users:
                user = user.split(', ')
                cur_online[user[0]] = (user[1], int(user[2]))
        if received_message.startswith("Bye"):
            clientSocket.close()
            exit(0)
        if received_message == "Welcome to Tessenger!":
            logged_in = True
            message = str(client_udp_port)
            clientSocket.sendall(message.encode())
        if (received_message == "Invalid Password. Your account has been blocked. Please try again later" or
            received_message == "Your account is blocked due to multiple login failures. Please try again later"):    
            clientSocket.close()
            exit(0)

def receive_msg(socket):
    # every 0.1 seconds, print out received messages.
    while True:
        is_stopped.set()
        stop_event.wait()
        is_stopped.clear()
        try:
            data = socket.recv(1024)
            received_message = data.decode()
            print(received_message)
            print("Enter one of the following commands (/msgto, /activeuser, /creategroup, "
                        "/joingroup, /groupmsg, /p2pvideo, /logout: ")
        except:
            time.sleep(0.1)

# events to pause the thread for receiving messages from the server
stop_event = threading.Event()
is_stopped = threading.Event()



def udp_sender(message, cur_online):
    message = message[len("/p2pvideo "):].strip()
    username = message[:message.index(" ")]
    filename = message[len(username) + 1:].strip()
    if not os.path.isfile(filename):
        print(f"Path does not exist or is not a file.")
        return
    try:
        ip_address, port = cur_online[username]
    except:
        print(f"/activeuser has not been called since {username} was last online.")
        return
    udp_send_socket.sendto(f"{username}_{filename}".encode(), (ip_address, port))
    # wait for ack to continue
    udp_send_socket.recvfrom(1024)
    with open(filename, "rb") as file:
        while True:
            content = file.read(1024)
            if not content:
                content = "EOF_INDICATOR".encode()
                udp_send_socket.sendto(content, (ip_address, port))
                break
            udp_send_socket.sendto(content, (ip_address, port))
            time.sleep(0.0001)
    print(f"{filename} has been uploaded")
    print("Enter one of the following commands (/msgto, /activeuser, /creategroup, "
          "/joingroup, /groupmsg, /p2pvideo, /logout:")


def udp_receiver():
    while True:
        filename, address = udp_receiver_socket.recvfrom(1024)
        if filename.decode() == "EOF_INDICATOR": continue
        udp_receiver_socket.sendto("ack".encode(), address)
        with open(filename.decode(), "wb") as file:
            while True:
                content, _ = udp_receiver_socket.recvfrom(1024)
                if len(content) != 1024:
                    try:
                        if content.decode() != "EOF_INDICATOR":
                            file.write(content)
                    except:
                        file.write(content)
                    break
                file.write(content)
        print(f"Received {filename.decode().split('_')[1]} from {filename.decode().split('_')[0]}")
        print("Enter one of the following commands (/msgto, /activeuser, /creategroup, "
              "/joingroup, /groupmsg, /p2pvideo, /logout:")


udp_receiver_socket = socket(AF_INET, SOCK_DGRAM)
udp_receiver_socket.bind(('localhost', client_udp_port))

udp_send_socket = socket(AF_INET, SOCK_DGRAM)

udp_receiver_thread = threading.Thread(target=udp_receiver)
udp_receiver_thread.daemon = True
udp_receiver_thread.start()


# Allows keyboard interrupts to work
new_thread = threading.Thread(target=code_to_run)
new_thread.daemon = True
new_thread.start()
while new_thread.is_alive():
    time.sleep(0.4)