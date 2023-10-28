import datetime
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
message_number = 1  # 这应该是一个全局变量，脚本开始时进行初始化
message_log_lock = threading.Lock()

# 当前活跃的客户端数
current_clients = 0
# 存储失败尝试次数和封锁时间的字典
failed_attempts = {}
active_users = {}
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


def update_userlog(username, filename='userlog.txt'):
    with open(filename, 'r') as f:
        lines = f.readlines()

    new_lines = []
    user_found = False
    for line in lines:
        line_parts = line.strip().split(';')
        if line_parts[2].strip() == username:
            user_found = True
            continue
        if user_found:  # If the user has been found, update the sequence number of subsequent lines
            line_parts[0] = str(int(line_parts[0]) - 1)
            new_lines.append('; '.join(line_parts) + '\n')
        else:
            new_lines.append(line)

    with open(filename, 'w') as f:
        f.writelines(new_lines)


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

    while True:
        # 调用当前状态的 handle 方法并获取下一个状态
        next_state, username = current_state.handle(conn, credentials, failed_attempts, max_failed_attempts,
                                                    addr)
        # 如果到达了结束状态（这里以 True 为例），则退出循环
        if next_state is True:
            break
        # 更新当前状态
        current_state = next_state

    return True, username


def handle_client(conn, addr, credentials, max_failed_attempts):
    global current_clients, active_users, message_number
    with client_lock:
        if current_clients >= MAX_CLIENTS:
            conn.send(b'Server is too busy. Please try again later.\n')
            conn.close()
            return
        current_clients += 1
    try:
        print(f'Connection from {addr}')
        authenticated, username = authenticate(conn, credentials, failed_attempts, max_failed_attempts, addr)
        if authenticated:
            print(f'User {username} authenticated.')
            udp_port = conn.recv(1024).decode()
            utc_now = datetime.datetime.now()
            timestamp = utc_now.strftime('%d %b %Y %H:%M:%S')
            log_entry = f"{len(active_users) + 1}; {timestamp}; {username}; {addr[0]}; {udp_port}"
            logging.info(log_entry)
            active_users[username] = {
                'timestamp': datetime.datetime.now(),
                'addr': addr,
                'conn': conn  # 存储用户的连接
            }
            conn.send((commands + '\n').encode())

            # Command handling loop
            while True:
                user_input = conn.recv(1024).decode().strip()
                print(user_input)
                if user_input.startswith('/msgto'):
                    parts = user_input.split(' ', 2)
                    if len(parts) < 3:
                        conn.send(b'Error: Invalid command format. Expected: /msgto USERNAME MESSAGE_CONTENT\n')
                        continue
                    target_username = parts[1]
                    message_content = parts[2]

                    with message_log_lock:  # 使用锁来确保线程安全
                        with open('messagelog.txt', 'a') as file:
                            timestamp = time.strftime('%d %b %Y %H:%M:%S', time.gmtime())
                            log_entry = f"{message_number}; {timestamp}; {username}; {message_content}\n"
                            file.write(log_entry)
                            message_number += 1

                        confirmation = f"Broadcast message at {timestamp}\n"
                        conn.send(confirmation.encode())

                        if target_username in active_users:
                            target_conn = active_users[target_username]['conn']
                            target_message = f"Message from {username}: {message_content}\n"
                            target_conn.send(target_message.encode())
                        else:
                            conn.send(f"User {target_username} is not online.\n".encode())

                elif user_input == '/activeuser':
                    active_user_list = []
                    for user, info in active_users.items():
                        if user != username:  # Exclude the current user
                            timestamp = info['timestamp'].strftime('%d %b %Y %H:%M:%S')
                            formatted_info = f"{user}, active since {timestamp}."
                            active_user_list.append(formatted_info)

                    if active_user_list:
                        conn.send(('\n'.join(active_user_list) + '\n').encode())
                    else:
                        conn.send(b'No other active users.\n')
                elif user_input == '/creategroup':
                    pass
                elif user_input == '/joingroup':
                    pass
                elif user_input == '/groupmsg':
                    pass
                elif user_input == '/logout':
                    if username in active_users:
                        del active_users[username]
                    update_userlog(username)
                    conn.send("You have been logged out successfully.".encode())
                    conn.close()
                    break
                elif user_input == '/p2pvideo':
                    pass
                else:
                    error_message = "Invalid command selected. Please choose a valid command.\n"
                    conn.send((error_message + '\n' + commands + '\n').encode())

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
    with open('userlog.txt', 'w') as file:
        file.write('')
    with open('messagelog.txt', 'w') as file:
        file.write('')

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
