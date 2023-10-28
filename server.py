import logging
import socket
import sys
import time
import threading

from authenticate import RequestUsernameState

# 最大客户端连接数
MAX_CLIENTS = 5
# 线程锁
client_lock = threading.Lock()
# 锁用于保护 failed_attempts 字典
failed_attempts_lock = threading.Lock()

# 当前活跃的客户端数
current_clients = 0
# 存储失败尝试次数和封锁时间的字典
failed_attempts = {}
is_shutting_down = False

commands = """Available commands:
/msgto        : Private message to another active user.
/activeuser   : Display active users.
/creategroup  : Create a group chat room.
/joingroup    : Join an existing group chat room.
/groupmsg     : Send a message to a specific group.
/logout       : Log out.
/p2pvideo     : Send a video file to another active user via UDP."""

logging.basicConfig(filename='userlog.txt', level=logging.INFO, format='%(message)s')


# 加载凭证
def load_credentials(filename='credentials.txt'):
    credentials = {}
    with open(filename, 'r') as f:
        for line in f.readlines():
            username, password = line.strip().split(' ')
            credentials[username] = password
    return credentials


# 认证用户
# def authenticate(conn, credentials, max_failed_attempts, addr):
#     global failed_attempts
#     with failed_attempts_lock:
#         # 发送请求用户名的状态码
#         conn.send(b'100')
#         username = conn.recv(1024).decode()
#
#         # 发送请求密码的状态码
#         conn.send(b'101')
#         password = conn.recv(1024).decode()
#
#         # 初始化失败尝试次数和阻塞时间
#         if username not in failed_attempts:
#             failed_attempts[username] = {'count': 0, 'block_until': 0}
#
#         # 获取当前时间
#         current_time = time.time()
#
#         # 检查用户是否被阻塞
#         if current_time < failed_attempts[username]['block_until']:
#             conn.send(b'401')
#             return False, None, None
#
#         # 检查用户名和密码是否有效
#         if username in credentials and credentials[username] == password:
#             # 发送成功的状态码
#             conn.send(b'200')
#             # 获取 UDP 端口
#             udp_port = conn.recv(1024).decode()
#             # 记录时间戳和其他登录信息
#             timestamp = time.strftime('%d %b %Y %H:%M:%S', time.gmtime())
#             log_entry = f"{username}; {timestamp}; {addr[0]}; {udp_port}"
#             logging.info(log_entry)
#             # 重置失败尝试次数
#             failed_attempts[username]['count'] = 0
#             return True, username, udp_port
#         else:
#             # 发送失败的状态码
#             conn.send(b'400')
#             # 更新失败尝试次数
#             failed_attempts[username]['count'] += 1
#
#             # 检查是否需要阻塞用户
#             if failed_attempts[username]['count'] >= max_failed_attempts:
#                 failed_attempts[username]['block_until'] = current_time + 10
#                 conn.send(b'401')
#
#             return False, None, None


# 处理客户端连接
def authenticate(conn, credentials, failed_attempts, max_failed_attempts, addr):
    # 初始化状态为等待用户名输入
    current_state = RequestUsernameState()
    username, udp_port = None, None

    while True:
        # 调用当前状态的 handle 方法并获取下一个状态
        next_state, username, udp_port = current_state.handle(conn, credentials, failed_attempts, max_failed_attempts,
                                                              addr)

        # 如果到达了结束状态（这里以 True 为例），则退出循环
        if next_state is True:
            break

        # 更新当前状态
        current_state = next_state

    return True, username, udp_port


def handle_client(conn, addr, credentials, max_failed_attempts):
    global current_clients
    with client_lock:
        if current_clients >= MAX_CLIENTS:
            conn.send(b'Server is too busy. Please try again later.\n')
            conn.close()
            return
        current_clients += 1
    try:
        print(f'Connection from {addr}')
        authenticated, username, udp_port = authenticate(conn, credentials, failed_attempts, max_failed_attempts, addr)
        if authenticated:
            print(f'User {username} authenticated.')
            conn.send((commands+'\n').encode())

            # Command handling loop
            while True:
                user_input = conn.recv(1024).decode().strip()
                if user_input == '/msgto':
                    pass
                elif user_input == '/acitveuser':
                    pass
                elif user_input == '/creategroup':
                    pass
                elif user_input == '/joingroup':
                    pass
                elif user_input == '/groupmsg':
                    pass
                elif user_input == '/logout':
                    pass
                elif user_input == 'p2pvideo':
                    pass
                else:
                    error_message = "Invalid command selected. Please choose a valid command.\n"
                    conn.send(error_message.encode())
                    conn.send(commands.encode())

    finally:
        with client_lock:
            current_clients -= 1
        conn.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python server.py <server_port> <number_of_consecutive_failed_attempts>")
        sys.exit(1)

    server_port = int(sys.argv[1])
    max_failed_attempts = int(sys.argv[2])
    if max_failed_attempts < 1 or max_failed_attempts > 5:
        print(
            "Invalid number of allowed failed consecutive attempts. The valid value of the argument is an integer "
            "between 1 and 5.")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', server_port))
    server_socket.listen(5)

    credentials = load_credentials()
    threads = []

    try:
        while True:
            print('Waiting for a connection...')
            conn, addr = server_socket.accept()

            if is_shutting_down:  # 如果服务器正在关闭，就不接受新的连接
                conn.close()
                break

            client_thread = threading.Thread(target=handle_client, args=(conn, addr, credentials, max_failed_attempts))
            client_thread.start()
            threads.append(client_thread)  # 将新线程添加到列表中

    except KeyboardInterrupt:
        print("Shutting down the server...")
        is_shutting_down = True  # 设置全局标志以关闭所有线程

        for thread in threads:  # 等待所有线程完成
            thread.join()

        server_socket.close()
