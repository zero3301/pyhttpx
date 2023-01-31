

import socket
from base64 import b64encode

from pyhttpx.exception import ProxyError

__version__ = "0.0.1"

PROXY_TYPE_HTTP = HTTP = 1
DEFAULT_PORTS = {HTTP: 8080}

class SocketProxy(socket.socket):
    HTTP = 1
    def __init__(self, *args):
        super().__init__(*args)

    def set_proxy(self, proxy_type, proxy_addr,proxy_port, username=None, password=None):

        self.proxy = (proxy_type, proxy_addr, int(proxy_port),username,
         password)


    def connect(self, dest_pair):

        (proxy_type, proxy_addr, proxy_port, username,
        password) = self.proxy
        dest_addr = dest_pair[0]
        dest_port = dest_pair[1]


        http_headers = [
            (b"CONNECT " + dest_addr.encode("idna") + b":"
             + str(dest_port).encode() + b" HTTP/1.1"),
            b"Host: " + dest_addr.encode("idna")
        ]

        if username and password:
            http_headers.append(b"Proxy-Authorization: Basic "
                                + b64encode(username.encode('latin1') + b":" + password.encode('latin1')))

        http_headers.append(b"\r\n")
        try:
            super(SocketProxy, self).connect((proxy_addr, proxy_port))
            self.sendall(b"\r\n".join(http_headers))
            status_line = self.recv(1024).decode()
            proto, status_code, status_msg = status_line.split(" ", 2)
        except (socket.timeout, ConnectionRefusedError):
            raise ProxyError(
                "Proxy server connection time out")



        if not proto.startswith("HTTP/"):
            raise ProxyError(
                "Proxy server does not appear to be an HTTP proxy")

        status_code = int(status_code)
        if status_code != 200:
            error = ''
            #Tunnel connection failed: 502 Proxy Bad Server
            if status_code in (400, 403, 405):
                error = "The HTTP proxy server may not be supported"

            elif status_code in (407,):
                error =f'Tunnel connection failed: status_code = {status_code},Unauthorized'

            else:
                error = f'Tunnel connection failed: status_msg = {status_line}'

            raise ProxyError(error)
        return True

if __name__ == '__main__':
    sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s = SocketProxy()
    s.set_proxy(1, '127.0.0.1', 7890)
    s.connect(('www.baidu.com',443))
    print(s)
    print(s.getsockname())



