import socket
import sys

import select

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

inputs = [client_socket, sys.stdin]  # We want to check both the socket and stdin for input

while True:
    readable, _, _ = select.select(inputs, [], [])

    # Received something from the server
    if client_socket in readable:
        server_message = client_socket.recv(1024).decode()
        print(server_message, end='')  # This will print the message received from the server

    # User input from the command line
    if sys.stdin in readable:
        user_input = input()
        client_socket.send(user_input.encode())

# 关闭套接字
client_socket.close()
