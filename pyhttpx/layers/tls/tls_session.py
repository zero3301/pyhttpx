
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

from pyhttpx.layers.tls.keyexchange import ServerContext,ClientCpiherSpec,ClientKeyExchange
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

class TLSSocket():
    def __init__(self, host, port,proxies=None, timeout=None, **kwargs):
        self.kw = {}
        self.kw.update(kwargs)
        self._closed = True
        self.timeout = 0
        self.host = host
        self.port = port
        self.proxies = proxies
        self.timeout = timeout

    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)

    def connect(self):
        self.servercontext = ServerContext()
        self.tls_cxt = TLSSessionCtx()
        self.tls_cxt.handshake_data = []

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.timeout = self.timeout or 0
        if self.proxies:

            self.socket = SocketProxy()
            proxy_ip, proxy_port = self.proxies['https'].split(':')
            self.socket.set_proxy(SocketProxy.HTTP, proxy_ip, proxy_port,'hwq','123456')

        try:
            self.socket.connect((self.host, self.port))

        except (ConnectionRefusedError,TimeoutError,socket.timeout):
            raise ConnectionTimeout('无法连接 %s:%s' % (self.host, self.port))

        else:
            self.local_ip, self.local_port = self.socket.getsockname()[:2]
            self.remote_ip, self.remote_port = self.socket.getpeername()[:2]
            self.isclosed = False
            return self._tls_do_handshake()

    def _tls_do_handshake(self):

        ciphersuites, extensions = CipherSuites(**self.kw).dump(),dump_extension(self.host, **self.kw)
        hello = HelloClient(ciphersuites, extensions)
        self.tls_cxt.client_ctx.random = hello.hanshake.random
        self.socket.sendall(hello.dump(self.tls_cxt))

        exchanage  = True
        cache =b''
        self.server_change_cipher_spec = False
        while True:
            try:
                recv = self.socket.recv(6324)

            except (ConnectionRefusedError,ConnectionResetError,socket.timeout):
                raise ConnectionTimeout('无法连接 %s:%s' % (self.host, self.port))
            #socket.timeout
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

                        #在发送verify_data处理握手层数据
                        if not self.server_change_cipher_spec:
                            self.tls_cxt.handshake_data.append(flowtext)
                            self.servercontext.load(flowtext)

                        if not exchanage and self.server_change_cipher_spec:
                            #print(threading.current_thread().name,'成功握手,server Encrypted Handshake Message')
                            # 验证服务器消息,Encrypted Handshake Message,效验密钥

                            server_verify_data = self.tls_cxt.decrypt(flowtext, b'\x16')
                            self.tls_cxt.verify_server_message(server_verify_data)
                            return True

                    elif handshake_type == 0x14:
                        self.server_change_cipher_spec = True
                    elif handshake_type == 0x15:
                        raise TLSDecryptErrorExpetion('handshake failed!, Server Decrypt Error')
                    recv = recv[5+length:]

                if self.servercontext.done and exchanage:

                    self.tls_cxt.server_ctx.random = self.servercontext.serverstore.random
                    self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                    self.tls_cxt.rsa_pulicKey = self.servercontext.certificatecontext.rsa_pulicKey
                    self.tls_cxt.curve_name = self.servercontext.curve_name
                    self.tls_cxt.server_ecdhe_pubkey = self.servercontext.serverpubkey
                    if 23 in self.servercontext.serverstore.ext.keys():
                        self.tls_cxt.extended_master_secret  =True

                    #加载相关套件
                    self.tls_cxt.load_alg()

                    keychange = ClientKeyExchange(self.tls_cxt.publickey_bytes).dump(self.tls_cxt)
                    changecipherspec =  ClientCpiherSpec().dump()

                    #加载客户端verify_data后再导出密钥
                    self.tls_cxt.load_key()

                    verify_data = self.tls_cxt.get_verify_data()
                    ciphertext = self.tls_cxt.encrypt(verify_data, b'\x16')
                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext )) + ciphertext
                    self.socket.sendall(keychange + changecipherspec + encrypted_message)
                    exchanage = False

    def sendall(self, data):
        try:
            self.socket.sendall(data)
        except ConnectionError as e:
            pass

    def flush(self):
        if self.write_buff:
            send_num = 0
            while True:
                try:
                    send_num += 1
                    self.sendall(self.write_buff)
                except (ConnectionError):
                    self.connect()
                    if send_num > 3:
                        raise ConnectionError('Reconnect more than %s' % send_num)
                else:
                    break

        self.write_buff = None
        self.plaintext_buffer_reader = []
        cache = b''
        while True:
            #timeout=0,会设置非阻塞
            self.timeout > 0 and self.socket.settimeout(self.timeout)

            try:
                recv = self.socket.recv(6324)
            except ConnectionAbortedError:
                raise ConnectionAbortedError('ConnectionAbortedError')

            except socket.timeout:
                raise ReadTimeout('timed out')

            if not recv:
                # 服务器不保持长连接,传输完毕断开连接
                self.isclosed = True
                return -1
                #raise ConnectionClosed('Server closes connection')

            recv = cache + recv
            cache = b''
            while recv and len(recv) >= 5:
                handshake_type = struct.unpack('!B', recv[:1])[0]
                length = struct.unpack('!H', recv[3:5])[0]
                flowtext = recv[5:5 + length]
                if len(flowtext) != length:
                    cache = recv[:]
                    break

                recv = recv[5 + length:]
                if handshake_type == 0x17:
                    plaintext = self.tls_cxt.decrypt(flowtext, b'\x17')
                    self.response.flush(plaintext)
                    if self.response.read_ended:
                        return True

                elif handshake_type == 0x15:
                    self.isclosed = True
                    raise ConnectionClosed('Server Encrypted Alert')


    def send(self, plaintext):

        self.response = Response(tls_ctx=self)
        ciphertext = self.tls_cxt.encrypt(plaintext, b'\x17')
        self.write_buff = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
        return self.flush()

