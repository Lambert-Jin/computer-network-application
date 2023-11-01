import os
import socket
import sys
import threading
import time

user_data = {}

received_data = b""
filename = None
UDP_BUFFER_SIZE = 1024


def print_user_data():
    for username, details in user_data.items():
        ip = details['ip']
        port = details['port']
        print(f"Username: {username}, IP: {ip}, Port: {port}")


def get_activeuser(response):
    # Clear the dictionary at the start
    user_data.clear()

    lines = response.strip().split('\n')

    # If the response indicates no other active users, just return.
    if lines[0] == "No other active users.":
        return

    # Otherwise, parse each line and update the dictionary.
    for line in lines:
        parts = line.split(', ')
        username = parts[0].strip()
        ip = parts[1].strip()
        port = int(parts[2].strip())
        # Storing the data in the global dictionary
        user_data[username] = {'ip': ip, 'port': port}

    # print_user_data()


def is_user_active(username):
    return username in user_data


def is_file_present(filename):
    return os.path.exists(filename)


def receive_from_server(sock):
    while True:
        server_message = sock.recv(1024).decode()
        if not server_message:
            print("Server disconnected. Exiting.")
            sys.exit()
        # Check if the message starts with the activeuser response identifier
        if server_message.startswith("ACTIVEUSER_RESPONSE:"):
            print(server_message.replace("ACTIVEUSER_RESPONSE:", "", 1), end='')
            # Strip the identifier and process the rest of the message
            get_activeuser(server_message.replace("ACTIVEUSER_RESPONSE:", "", 1))
        else:
            print(server_message, end='')


def send_file_udp(filename, target_ip, target_port):
    FILE_SIZE = 1024  # Size of the chunks we'll use to send the file
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send the length of the filename
    udp_socket.sendto(str(len(filename)).encode(), (target_ip, target_port))
    # Send the filename
    udp_socket.sendto(filename.encode(), (target_ip, target_port))

    # Send the file data
    with open(filename, 'rb') as file:
        while True:
            data = file.read(FILE_SIZE)
            time.sleep(0.001)
            if not data:
                break  # File reading is done
            udp_socket.sendto(data, (target_ip, target_port))
    udp_socket.sendto(b'FILE_TRANSFER_COMPLETE', (target_ip, target_port))
    udp_socket.close()


def p2pvideo(command):
    parts = command.split()
    if len(parts) != 3:
        print("Error: Invalid format. Use: /p2pvideo username filename")
        return

    _, target_username, filename = parts

    if not is_user_active(target_username):
        print(f"Error: {target_username} is offline.")
        return

    if not is_file_present(filename):
        print(f"Error: File {filename} does not exist.")
        return

    target_ip = user_data[target_username]['ip']
    target_port = user_data[target_username]['port']

    send_file_udp(filename, target_ip, target_port)
    print(f"File {filename} sent to {target_username}.")


def udp_server_listener():
    global received_data
    global filename

    udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server_socket.bind(('0.0.0.0', client_udp_server_port))

    while True:
        # Receive the length of the filename
        length, _ = udp_server_socket.recvfrom(UDP_BUFFER_SIZE)
        filename_length = int(length.decode())

        # Receive the filename
        filename = udp_server_socket.recvfrom(filename_length)[0].decode()

        # Receive the file data
        with open(filename, 'wb') as file:
            while True:
                data, addr = udp_server_socket.recvfrom(UDP_BUFFER_SIZE)
                if data == b'FILE_TRANSFER_COMPLETE':
                    break
                file.write(data)

        print(f"A file ({filename}) has been received from {addr[0]}")
        filename = None
        received_data = b""


# -----------------------
if len(sys.argv) != 4:
    print("Usage: python client.py <server_IP> <server_port> <client_udp_server_port>")
    sys.exit(1)

# 解析命令行参数
server_IP = sys.argv[1]
server_port = int(sys.argv[2])
client_udp_server_port = int(sys.argv[3])

# 创建 TCP 套接字并连接到服务器
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_IP, server_port))

# 用户认证流程
while True:
    # 接收服务器状态码
    server_code = client_socket.recv(1024).decode()

    # 根据状态码进行相应操作
    if server_code == '100':  # 请求输入用户名
        user_input = input("Please enter your username: ")
        client_socket.send(user_input.encode())
    elif server_code == '101':  # 请求输入密码
        user_input = input("Please enter your password: ")
        client_socket.send(user_input.encode())
    elif server_code == '200':  # 登录成功
        print("You are successfully logged in.")
        # 发送UDP端口（如果需要）
        client_socket.send(str(client_udp_server_port).encode())
        break
    elif server_code == '400':  # 登录失败
        print("Invalid username or password, please try again.")
    elif server_code == '401':  # 账户被阻塞
        print("You have been blocked due to multiple failed attempts. Please try again later.")
# 在这里添加更多客户端功能，例如接收命令、发送消息等。

threading.Thread(target=receive_from_server, args=(client_socket,)).start()
threading.Thread(target=udp_server_listener, daemon=True).start()
while True:
    user_input = input()
    if user_input == '/logout':
        client_socket.send('/logout'.encode())
        response = client_socket.recv(1024).decode()
        print(response)
        client_socket.close()
        break
    elif user_input.startswith('/p2pvideo'):
        p2pvideo(user_input)
    else:
        client_socket.send(user_input.encode())
