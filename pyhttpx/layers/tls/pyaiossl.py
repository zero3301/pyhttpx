"""
TLS session handler.
"""

import socket
import struct
import time
import platform
import sys
import importlib
import threading

import asyncio
import os
import socket
import threading

from pyhttpx.layers.tls.keyexchange import ServerContext, ClientCpiherSpec, ClientKeyExchange
from pyhttpx.layers.tls.handshake import HelloClient
from pyhttpx.layers.tls.suites import CipherSuites
from pyhttpx.layers.tls.extensions import dump_extension

from pyhttpx.layers.tls.tls_context import TLSSessionCtx

from pyhttpx.models import Response

from pyhttpx.exception import (
    TLSDecryptErrorExpetion,
    ConnectionTimeout,
    ConnectionClosed,
    ReadTimeout)

from pyhttpx.layers.tls.socks import SocketProxy
from pyhttpx.utils import vprint


class TLSSocket:
    def __init__(self, sock=None, server_hostname=None, proxies=None, timeout=None, **kwargs):
        super().__init__()
        self.kw = {}
        self.kw.update(kwargs)
        self._closed = True
        self._timeout = 0
        self.server_hostname = server_hostname
        self.proxies = proxies
        self._timeout = timeout
        self.sock = sock

    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)

    async def connect(self, addres=None):
        self.servercontext = ServerContext()
        self.tls_cxt = TLSSessionCtx()
        self.tls_cxt.handshake_data = []
        self.host, self.port = addres[0], addres[1]

        self._timeout = self._timeout or 0

        await self._tls_do_handshake()

    async def _tls_do_handshake(self):

        ciphersuites, extensions = CipherSuites(**self.kw).dump(), dump_extension(self.host, **self.kw)
        hello = HelloClient(ciphersuites, extensions)
        self.tls_cxt.client_ctx.random = hello.hanshake.random
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port)


        self.writer.write(hello.dump(self.tls_cxt))
        exchanage = True
        cache = b''
        self.server_change_cipher_spec = False
        while True:
            try:
                recv = await self.reader.read(6324)

            except (ConnectionRefusedError, ConnectionResetError, socket.timeout):
                raise ConnectionTimeout('无法连接 %s:%s' % (self.host, self.port))

            recv = cache + recv
            cache = b''

            if recv:
                while recv:
                    handshake_type = struct.unpack('!B', recv[:1])[0]
                    length = struct.unpack('!H', recv[3:5])[0]
                    flowtext = recv[5:5 + length]
                    if len(flowtext) != length:
                        cache = recv[:]
                        break

                    if handshake_type == 0x16:

                        # 在发送verify_data处理握手层数据
                        if not self.server_change_cipher_spec:
                            self.tls_cxt.handshake_data.append(flowtext)
                            self.servercontext.load(flowtext)

                        if not exchanage and self.server_change_cipher_spec:
                            # print(threading.current_thread().name,'成功握手,server Encrypted Handshake Message')
                            # 验证服务器消息,Encrypted Handshake Message,效验密钥

                            server_verify_data = self.tls_cxt.decrypt(flowtext, b'\x16')
                            self.tls_cxt.verify_server_message(server_verify_data)
                            return True

                    elif handshake_type == 0x14:
                        self.server_change_cipher_spec = True
                    elif handshake_type == 0x15:
                        raise TLSDecryptErrorExpetion('handshake failed!, Server Decrypt Error')
                    recv = recv[5 + length:]

                if self.servercontext.done and exchanage:

                    self.tls_cxt.server_ctx.random = self.servercontext.serverstore.random
                    self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                    self.tls_cxt.rsa_pulicKey = self.servercontext.certificatecontext.rsa_pulicKey
                    self.tls_cxt.curve_name = self.servercontext.curve_name
                    self.tls_cxt.server_ecdhe_pubkey = self.servercontext.serverpubkey
                    if 23 in self.servercontext.serverstore.ext.keys():
                        self.tls_cxt.extended_master_secret = True

                    # 加载相关套件
                    self.tls_cxt.load_alg()

                    keychange = ClientKeyExchange(self.tls_cxt.publickey_bytes).dump(self.tls_cxt)
                    changecipherspec = ClientCpiherSpec().dump()

                    # 加载客户端verify_data后再导出密钥
                    self.tls_cxt.load_key()

                    verify_data = self.tls_cxt.get_verify_data()
                    ciphertext = self.tls_cxt.encrypt(verify_data, b'\x16')
                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
                    self.writer.write(keychange + changecipherspec + encrypted_message)
                    exchanage = False


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    async def sendall(self, plaintext):
        ciphertext = self.tls_cxt.encrypt(plaintext, b'\x17')
        self.write_buff = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
        self.writer.write(self.write_buff)
        self.cache = b''
        self.plaintext_reader = b''

    async def recv(self, size=1024):

        s = await self.reader.read(6324)
        if not s:
            return None

        s = self.cache + s
        self.cache = b''

        # 会存在读取长度不足而返回空字符,而不是收到fin
        while s and len(s) >= 5:

            handshake_type = struct.unpack('!B', s[:1])[0]
            length = struct.unpack('!H', s[3:5])[0]
            flowtext = s[5:5 + length]

            if len(flowtext) < length:
                self.cache = s[:]
                break

            s = s[5 + length:]
            if handshake_type == 0x17:
                p = self.tls_cxt.decrypt(flowtext, b'\x17')
                self.plaintext_reader += p

            elif handshake_type == 0x15:
                self.isclosed = True

        b = self.plaintext_reader
        self.plaintext_reader = b''
        return b



PROTOCOL_TLSv1_2 = b'\x03\x03'


class SSLContext:
    check_hostname: bool = False

    def __init__(self, protocol=None):
        self.protocol = protocol

    def wrap_socket(self, sock=None, server_hostname=None, **kwargs):
        return TLSSocket(sock=sock, server_hostname=server_hostname, **kwargs)

    def load_cert_chain(self, certfile: str, ketfile: str):
        pass

    def set_ciphers(self, ciphers: str):
        pass



async def get():
    host = '127.0.0.1'
    host = 'httpbin.org'
    host = 'www.baidu.com'
    host = 'premws-pt3.365lpodds.com'
    port = 443
    addres = (host, port)
    context = SSLContext(PROTOCOL_TLSv1_2)

    sock = context.wrap_socket()
    await sock.connect(addres)

    m = 'GET / HTTP/1.1\r\n\r\n'
    await sock.sendall(m.encode())
    data = await sock.recv(8888)

    print(data)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    loop.run_until_complete(get())





