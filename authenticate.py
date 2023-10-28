import logging
import time
from abc import ABC, abstractmethod


class AuthState(ABC):
    @abstractmethod
    def handle(self, conn, credentials, failed_attempts, max_failed_attempts, addr):
        pass


class RequestUsernameState(AuthState):
    def handle(self, conn, credentials, failed_attempts, max_failed_attempts, addr):
        conn.send(b'100')
        username = conn.recv(1024).decode()
        return RequestPasswordState(username), username, None


class RequestPasswordState(AuthState):
    def __init__(self, username):
        self.username = username

    def handle(self, conn, credentials, failed_attempts, max_failed_attempts, addr):
        conn.send(b'101')
        password = conn.recv(1024).decode()
        if self.username in credentials and credentials[self.username] == password:
            return LoginSuccessState(self.username), self.username, None
        else:
            return LoginFailedState(self.username), self.username, None


class LoginSuccessState(AuthState):
    def __init__(self, username):
        self.username = username

    def handle(self, conn, credentials, failed_attempts, max_failed_attempts, addr):
        conn.send(b'200')
        udp_port = conn.recv(1024).decode()
        timestamp = time.strftime('%d %b %Y %H:%M:%S', time.gmtime())
        log_entry = f"{self.username}; {timestamp}; {addr[0]}; {udp_port}"
        logging.info(log_entry)
        if self.username in failed_attempts:
            failed_attempts[self.username]['count'] = 0
        return True, self.username, udp_port


class LoginFailedState(AuthState):
    def __init__(self, username):
        self.username = username

    def handle(self, conn, credentials, failed_attempts, max_failed_attempts, addr):
        current_time = time.time()
        if self.username not in failed_attempts:
            conn.send(b'400')
            failed_attempts[self.username] = {'count': 1, 'block_until': 0}
            return RequestUsernameState(), self.username, None
        else:
            if failed_attempts[self.username]['block_until'] == 0:
                failed_attempts[self.username]['count'] += 1
                if failed_attempts[self.username]['count'] >= max_failed_attempts:
                    failed_attempts[self.username]['block_until'] = current_time + 10
                    conn.send(b'401')
                    return RequestUsernameState(), self.username, None
                else:
                    conn.send(b'400')
                    return RequestUsernameState(), self.username, None
            else:
                if current_time < failed_attempts[self.username]['block_until']:
                    conn.send(b'401')  # 仍在阻塞状态
                    return RequestUsernameState(), self.username, None

                # 解除阻塞和重置状态
                if current_time >= failed_attempts[self.username]['block_until']:
                    conn.send(b'400')
                    failed_attempts[self.username] = {'count': 0, 'block_until': 0}
                    return RequestUsernameState(), self.username, None


