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
group_message_log_lock = threading.Lock()

# 当前活跃的客户端数
current_clients = 0
# 存储失败尝试次数和封锁时间的字典
failed_attempts = {}
active_users = {}
groups = {}
user_sockets = {}

commands = """Enter one of the following commands (/msgto, /activeuser, /creategroup,
/joingroup, /groupmsg, /logout): """

logging.basicConfig(filename='userlog.txt', level=logging.INFO, format='%(message)s')


def get_online_users():
    online_users = set()
    with open('userlog.txt', 'r') as f:
        for line in f.readlines():
            parts = line.strip().split(';')
            online_users.add(parts[2].strip())  # 获取用户名并添加到集合中
    return online_users


def check_usernames_validity(usernames):
    online_users = get_online_users()
    for username in usernames:
        if username not in online_users:
            return False, username
    return True, None


def msgto(conn, username, user_input, active_users, message_log_lock):
    print(f'{username} issued /msgto command\n')
    global message_number
    parts = user_input.split(' ', 2)
    if len(parts) < 3:
        conn.send(b'Error: Invalid command format. Expected: /msgto USERNAME MESSAGE_CONTENT\n\n')
        print(f'Return message: invalid command format\n')
        return
    target_username = parts[1]
    message_content = parts[2]

    if target_username == username:
        conn.send(b'Error: can not send message to yourself\n\n')
        print(f'Return message: can not send message to yourself\n')
        return

    with message_log_lock:  # 使用锁来确保线程安全
        with open('messagelog.txt', 'a') as file:
            timestamp = time.strftime('%d %b %Y %H:%M:%S', time.localtime())
            log_entry = f"{message_number}; {timestamp}; {username}; {message_content}\n"
            file.write(log_entry)
            message_number += 1

        confirmation = f'message sent at {timestamp}\n\n'
        conn.send(confirmation.encode())
        print(f'{username} message to {target_username} "{message_content}" at {timestamp}\n')

        if target_username in active_users:
            target_conn = active_users[target_username]['conn']
            target_message = f"\n\n{timestamp}, {username}: {message_content}\n\n"
            target_conn.send(target_message.encode())
            target_conn.send(commands.encode())
        else:
            conn.send(f"User {target_username} is not online.\n\n".encode())
            print(f'Return message: targer user is not online\n')


def activeuser(conn, username, active_users):
    print(f'{username} issued /activeuser command\n')
    active_user_list = []
    for user, info in active_users.items():
        if user != username:  # Exclude the current user
            timestamp = time.strftime('%d %b %Y %H:%M:%S', info['timestamp'])
            address = info['IP']
            port = info['udp_port']
            formatted_info = f"{user}, {address}, {port}, active since {timestamp}."
            active_user_list.append(formatted_info)

    if active_user_list:
        conn.send(('ACTIVEUSER_RESPONSE:' + '\n'.join(active_user_list) + '\n\n').encode())
        print(f'Return messages:\n' + '\n'.join(active_user_list) + '\n')
    else:
        conn.send(b'ACTIVEUSER_RESPONSE:No other active users.\n\n')
        print(f'Return Messgae: No other active users.\n')


def creategroup(conn, username, user_input):
    print(f'{username} issued /creategroup command\n')
    parts = user_input.split()
    if len(parts) < 3:
        conn.send(b"Error: Provide a group name and at least one username.\n\n")
        print(f'Return message: not enough parameter in command\n')
        return

    groupname = parts[1]
    usernames = parts[2:]
    usernames.append(username)

    validity, target = check_usernames_validity(usernames)
    if not validity:
        conn.send(f'User {target} is not an active user.\n\n'.encode())
        print(f'Return message: targer user is not online\n')
        return
        # 检查组名是否已经存在
    if groupname in groups:
        conn.send(f'A group chat (Name: {groupname}) already exists.\n\n'.encode())
        print(f'Return message: fail to create a group, existed group name\n')
        return
        # 检查组名的有效性
    if not groupname.isalnum():
        conn.send(b"Error: Group name must only consist of letters and numbers.\n\n")
        print(f'Return message: fail to create a group, invalid group name\n')
        return
        # 创建组并加入成员
    groups[groupname] = {user: False for user in [username] + usernames}
    # 将创建者设置为已加入状态
    groups[groupname][username] = True
    # 创建对应的日志文件
    with open(f"{groupname}_messagelog.txt", 'w') as file:
        pass  # 创建一个空文件
    usernames_str = ', '.join(usernames)
    conn.send(
        f"Group chat created with name: {groupname}, users in this room: {usernames_str}\n\n".encode())

    print(f'Return message: Group chat room has been created, room name: {groupname}, users in this room: {usernames_str}\n')

def joingroup(conn, username, user_input):
    print(f'{username} issued /joingroup command\n')
    parts = user_input.split()
    if len(parts) != 2:
        conn.send(b"Error: Provide a group name to join.\n\n")
        print(f'Return message: error message, not enough parameter\n')
        return

    groupname = parts[1]

    # 检查群组是否存在
    if groupname not in groups:
        conn.send(f"No group chat with name: {groupname} exists.\n\n".encode())
        print(f'Return message:\n{username} fail to join the group {groupname}, nonexistent group name\n')
        return

    # 检查用户是否被邀请加入群组
    if username in groups[groupname]:
        groups[groupname][username] = True
        conn.send(f"You have successfully joined the group chat: {groupname}\n\n".encode())
        print(f'Return message:\n{username} join the group {groupname} successfully\n')
    else:
        conn.send(f"You have not been invited to join the group chat: {groupname}\n\n".encode())
        print(f'Return message:\n{username} fail to join the group {groupname} since have been invited\n')


def groupmsg(conn, username, user_input):
    print(f'{username} issued /groupmsg command\n')
    parts = user_input.split(' ', 2)
    if len(parts) < 3:
        conn.send(b"Error: Provide a group name and a message.\n\n")
        print(f'Return message:\nerror message, not enough parameter\n')
        return

    groupname, message = parts[1], parts[2]

    # 检查组是否存在
    if groupname not in groups:
        conn.send(b"The group chat does not exist.\n\n")
        print(f'Return message:\n{username} fail to send the group message in group {groupname}, nonexistent group\n')
        return

        # 检查用户是否是组的成员
    if username not in groups[groupname]:
        conn.send(b"You are not in this group chat.\n\n")
        print(f'Return message:\n{username} fail to send the group message in group {groupname}, not in this group\n')
        return

    if not groups[groupname][username]:
        conn.send(b"You are invited but have not joined in this group chat.\n\n")
        print(f'Return message: {username} fail to send the group message in group {groupname}, invited but have not joined\n')
        return

        # 将消息添加到日志文件
    with group_message_log_lock:
        with open(f"{groupname}_messageLog.txt", 'a') as file:
            timestamp = time.strftime('%d %b %Y %H:%M:%S', time.localtime())
            number = sum(1 for line in open(f"{groupname}_messageLog.txt")) + 1
            log_entry = f"{number}; {timestamp}; {username}; {message}\n"
            file.write(log_entry)

    confirmation_msg = f"Group chat message sent. Message number: {number}, Timestamp: {timestamp}\n\n"
    conn.send(confirmation_msg.encode())
    print(f'Return message: {username} successfully send an message in group {groupname}\n')

    formatted_time = time.strftime('%d/%m/%Y %H:%M', time.localtime())
    formatted_message = f"\n\n{formatted_time}, {groupname}, {username}: {message}\n\n"

    # 转发消息给组中的所有其他活跃成员
    for user, has_joined in groups[groupname].items():
        if has_joined and user != username:
            user_socket = user_sockets.get(user)
            if user_socket:
                user_socket.send(formatted_message.encode())
                user_socket.send(commands.encode())


def logout(conn, username, active_users, user_sockets):
    print(f'{username} issued /logout command\n')
    if username in active_users:
        del active_users[username]
    update_userlog(username)
    if username in user_sockets:
        del user_sockets[username]
    print(f'Return message: {username} logout successfully\n')
    return True


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
            user_sockets[username] = conn
            print(f'User {username} authenticated.')
            udp_port = conn.recv(1024).decode()
            timestamp = time.strftime('%d %b %Y %H:%M:%S', time.localtime())
            log_entry = f"{len(active_users) + 1}; {timestamp}; {username}; {addr[0]}; {udp_port}"
            logging.info(log_entry)
            active_users[username] = {
                'timestamp': time.localtime(),
                'IP': addr[0],
                'udp_port': udp_port,
                'addr': addr,
                'conn': conn  # 存储用户的连接
            }
            conn.send(commands.encode())

            # Command handling loop
            while True:
                user_input = conn.recv(1024).decode().strip()
                if user_input.startswith('/msgto'):
                    msgto(conn, username, user_input, active_users, message_log_lock)
                    conn.send(commands.encode())
                elif user_input == '/activeuser':
                    activeuser(conn, username, active_users)
                    conn.send(commands.encode())
                elif user_input.startswith('/creategroup'):
                    creategroup(conn, username, user_input)
                    conn.send(commands.encode())
                elif user_input.startswith('/joingroup'):
                    joingroup(conn, username, user_input)
                    conn.send(commands.encode())
                elif user_input.startswith('/groupmsg'):
                    groupmsg(conn, username, user_input)
                    conn.send(commands.encode())
                elif user_input == '/logout':
                    if logout(conn, username, active_users, user_sockets):
                        break
                else:
                    error_message = "Invalid command selected. Please choose a valid command.\n"
                    conn.send((error_message + '\n' + commands).encode())

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
    server_socket.bind(('127.0.0.1', server_port))
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
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, credentials, max_failed_attempts))
            client_thread.start()
            threads.append(client_thread)  # 将新线程添加到列表中

    except KeyboardInterrupt:
        print("Shutting down the server...")
        server_socket.close()
