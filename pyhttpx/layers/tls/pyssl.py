
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

from pyhttpx.exception import (
    TLSDecryptErrorExpetion,
    ConnectionTimeout,
    ConnectionClosed,
    TLSHandshakeFailed,
    ProxyError,
    ReadTimeout)

from pyhttpx.layers.tls.socks import SocketProxy


PROTOCOL_TLSv1_2 = b'\x03\x03'
PROTOCOL_TLSv1_3 = b'\x03\x04'
def default_context():
    return SSLContext(PROTOCOL_TLSv1_2)


class SSLContext:

    def __init__(self, protocol=None, http2=True):
        self.protocol = protocol
        self.check_hostname: bool = False
        self.ciphers = None
        self.exts = None
        self.exts_payload = None
        self.supported_groups = None
        self.supported_groups = None
        self.ec_points = None
        self.browser_type = None
        self.http2 = http2
        self.application_layer_protocol_negotitaion = 'http/1.1'
        self.tlsversion = b'\x03\x03'


    def set_payload(self, browser_type=None, ja3=None, exts_payload=None):
        self.browser_type = browser_type or 'chrome'
        self.exts_payload = exts_payload

        if ja3:
            self.ja3 = ja3
        else:
            if self.browser_type == 'chrome':

                randarr = [6682,19018,64250, 47802]
                exts = f'{randarr[1]}-65281-18-27-43-0-5-51-13-11-17513-35-45-23-16-10-{randarr[3]}-21'
                self.ja3 = f"771,{randarr[0]}-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,{exts},{randarr[2]}-29-23-24,0"
                self.exts_payload = {47802: b'\x00'}


            else:
                #firefox_ja3
                self.ja3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0"

        self.protocol, self.ciphers, self.exts, self.supported_groups, self.ec_points = self.ja3.split(',')
        self.ciphers = [int(i) for i in self.ciphers.split('-')]
        self.exts = [int(i) for i in self.exts.split('-')]
        self.supported_groups = [int(i) for i in self.supported_groups.split('-')]
        self.ec_points = [int(i) for i in self.ec_points.split('-')]

        self.supported_groups = b''.join([struct.pack('!H', i) for i in self.supported_groups])
        self.ec_points = b''.join([struct.pack('!B', i) for i in self.ec_points])

    def wrap_socket(self, sock=None, server_hostname=None):
        return TLSSocket(sock=sock,server_hostname=server_hostname, ssl=self)

    def load_cert_chain(self, certfile: str, ketfile: str):
        pass

class TLSSocket():
    def __init__(self,sock=None, server_hostname=None,ssl=None):

        self._closed = True
        self.server_hostname = server_hostname
        self.sock = sock
        self.context = ssl or default_context()

        self.tls13 = False

    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)

    def connect(self,addres, timeout=None, proxies=None, proxy_auth=None):
        self.servercontext = ServerContext()
        self.tls_cxt = TLSSessionCtx()
        self.context.group_x25519_key = self.tls_cxt.group_x25519_key
        self.context.group_secp_key = self.tls_cxt.group_secp_key
        self.tls_cxt.handshake_data = []
        self.host,self.port = addres[0],int(addres[1])
        self.proxy_auth = proxy_auth
        if not self.sock:          
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.timeout  = timeout
        self.proxies = proxies
        
        if self.proxies and self.proxies.get('https'):
            self.sock = SocketProxy(socket.AF_INET, socket.SOCK_STREAM)
            proxy = self.proxies['https']
            if not ':' in proxy:
                raise ProxyError(f'ProxyError: {proxy}')
            proxy_ip, proxy_port = proxy.split(':')
            if self.proxy_auth:
                username,password = proxy_auth[0], proxy_auth[1]
            else:
                username, password = None,None

            self.sock.set_proxy(SocketProxy.HTTP, proxy_ip, proxy_port,username, password )

        try:
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

        except (ConnectionRefusedError,TimeoutError,socket.timeout):
            raise ConnectionTimeout(f'unable to connect {self.host}:{self.port}')

        else:
            self.local_ip, self.local_port = self.sock.getsockname()[:2]
            self.remote_ip, self.remote_port = self.sock.getpeername()[:2]
            self.isclosed = False
            return self._tls_do_handshake13()


    def _tls_do_handshake13(self):

        ciphersuites, extensions = CipherSuites(self.context).dump(),dump_extension(self.host,self.context)
        hello = HelloClient(ciphersuites, extensions)
        self.tls_cxt.client_ctx.random = hello.hanshake.random
        self.sock.sendall(hello.dump(self.tls_cxt))

        self.server_change_cipher_spec = False
        exchanage = True

        while True:
            length = 5
            recv_len = length

            head_flowtext = b''
            while len(head_flowtext) < length:
                s = self.mutable_recv(recv_len)
                if not s:
                    raise TLSHandshakeFailed('handshake failed')

                head_flowtext += s
                recv_len = length - len(head_flowtext)

            content_type = struct.unpack('!B', head_flowtext[:1])[0]
            length = struct.unpack('!H', head_flowtext[3:5])[0]
            flowtext = b''
            recv_len = length

            while len(flowtext) < length:

                s = self.mutable_recv(recv_len)
                if not s:
                    raise TLSHandshakeFailed('handshake failed')
                flowtext += s
                recv_len = length - len(flowtext)


            if content_type == 0x16:

                if not self.server_change_cipher_spec:

                    self.tls_cxt.handshake_data.append(flowtext)
                    while flowtext:
                        extlen = struct.unpack('!I', b'\x00' + flowtext[1:4])[0]

                        handshake_type = flowtext[0:1]
                        payload = flowtext[:4 + extlen]

                        self.servercontext.load(payload)
                        flowtext = flowtext[4 + extlen:]

                        if handshake_type == b'\x0d':
                            #证书请求
                            self.tls_cxt.certificate_request = True

                        elif handshake_type == b'\x0e':
                            self.servercontext.done = True

                    self.tls13 = True if self.servercontext.serverstore.ext.get(43) == b'\x03\x04' else False
                    self.tls_cxt.tls13 = self.tls13

                    # handle application_layer_protocol_negotitaion
                    if self.servercontext.serverstore.ext.get(16):
                        alpn = self.servercontext.serverstore.ext.get(16)[3:]
                        self.context.application_layer_protocol_negotitaion = alpn.decode('latin1')


                    if self.tls13:
                        self.server_change_cipher_spec = True
                        server_publickey = self.servercontext.serverstore.ext[51][4:]
                        self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                        self.tls_cxt.load_alg()
                        self.tls_cxt.make_secret(server_publickey)


                if not self.tls13:

                    if not exchanage and self.server_change_cipher_spec:
                        #tls1.2,成功握手,退出循环,server Encrypted Handshake Message'
                        # 验证服务器消息,Encrypted Handshake Message,效验密钥

                        server_verify_data = self.tls_cxt.decrypt(flowtext, b'\x16')
                        self.tls_cxt.verify_server_message(server_verify_data)

                        return True

            elif content_type == 0x14:
                if self.tls13:
                    pass
                    #server Change Cipher Spec
                    # self.server_change_cipher_spec = True
                    # server_publickey = self.servercontext.serverstore.ext[51][4:]
                    # self.tls_cxt.negotiated.ciphersuite = int(self.servercontext.serverstore.cipher_suit.hex(), 16)
                    # self.tls_cxt.load_alg()
                    # self.tls_cxt.make_secret(server_publickey)


                else:
                    self.server_change_cipher_spec = True


            elif content_type == 0x17:
                #tls1.3,握手数据是加密的
                plaintext = self.tls_cxt.decrypt(flowtext, b'\x17')
                self.tls_cxt.handshake_data.append(plaintext[:-1])

                plaintext, t = plaintext[:-1],plaintext[-1:]

                if t == b'\x16':
                    #握手类型会一起发送的情况

                    while plaintext:
                        extlen = struct.unpack('!I', b'\x00' + plaintext[1:4])[0]

                        handshake_type = plaintext[0]
                        payload = plaintext[4:4+extlen]
                        plaintext = plaintext[4+extlen:]

                        if handshake_type == 0x14:
                            # finished

                            certificate_data = bytes.fromhex('0b00000400000000')
                            changecipherspec = ClientCpiherSpec().dump()

                            if self.tls_cxt.certificate_request:
                                self.tls_cxt.handshake_data.append(certificate_data)
                                ciphertext = self.tls_cxt.encrypt(certificate_data + b'\x16', b'\x17')

                                data = b'\x17\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
                                self.sock.sendall(data)

                            self.sock.sendall(changecipherspec)
                            verify_data = self.tls_cxt.compute_verify_data()
                            ciphertext = self.tls_cxt.encrypt(verify_data, b'\x17')

                            data = b'\x17\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
                            self.sock.sendall(data)

                            #去掉certificate_request, 不然效验数据出错, 暂不清楚为什么
                            if self.tls_cxt.certificate_request:
                                self.tls_cxt.handshake_data.pop()

                            self.tls_cxt.derive_application_traffic_secret()

                            #ticket数据开始重置sequence
                            self.tls_cxt.server_ctx.sequence = 0
                            self.tls_cxt.client_ctx.sequence = 0

                            self.tls_cxt.server_ctx.crypto_alg.key = self.tls_cxt.server_application_write_key
                            self.tls_cxt.server_ctx.crypto_alg.fixed_iv = self.tls_cxt.server_application_write_iv

                            self.tls_cxt.client_ctx.crypto_alg.key = self.tls_cxt.client_application_write_key
                            self.tls_cxt.client_ctx.crypto_alg.fixed_iv = self.tls_cxt.client_application_write_iv
                            return


                        elif handshake_type == 0x0b:
                            #服务器证书11
                            pass

                        elif handshake_type == 0x0d:
                            #certificate request
                            pass
                            self.tls_cxt.certificate_request = True
                        elif handshake_type == 0x0f:
                            #证书服务器验证15
                            pass
                        elif handshake_type == 0x08:
                            #扩展
                            payload = payload[2:]
                            while payload:
                                ext_type = payload[:2]
                                extlen = struct.unpack('!H', payload[2:4])[0]
                                data = payload[4:4+extlen]
                                payload = payload[4+extlen:]
                                if ext_type == b'\x00\x10':
                                    self.context.application_layer_protocol_negotitaion = data[3:].decode('latin1')

                        elif handshake_type == 0x04:
                            #ticket有可能接受多个,所以交个下一阶段处理
                            pass


            elif content_type == 0x15:
                raise TLSDecryptErrorExpetion('handshake failed!, server encrypt error')


            if not self.tls13:
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

                    if self.tls_cxt.certificate_request:
                        #send client certificate
                        certificate = b'\x16\x03\x03\x00\x07' + bytes.fromhex('0b000003000000')
                        self.tls_cxt.handshake_data.append(bytes.fromhex('0b000003000000'))
                        self.sock.sendall(certificate)
                    keychange = ClientKeyExchange(self.tls_cxt.publickey_bytes).dump(self.tls_cxt)
                    changecipherspec = ClientCpiherSpec().dump()

                    # 加载客户端verify_data后再导出密钥
                    self.tls_cxt.load_key()

                    verify_data = self.tls_cxt.get_verify_data()
                    ciphertext = self.tls_cxt.encrypt(verify_data, b'\x16')
                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext

                    self.sock.sendall(keychange + changecipherspec + encrypted_message)
                    exchanage = False



    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def sendall(self, plaintext):
        n = 2 ** 12
        while plaintext:
            text = plaintext[:n]
            if self.tls13:
                text += b'\x17'

            ciphertext = self.tls_cxt.encrypt(text, b'\x17')
            write_buff = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
            self.sock.sendall(write_buff)
            plaintext = plaintext[n:]

        self.plaintext_reader = b''


    def mutable_recv(self, size=1024):
        try:
            self.sock.settimeout(self.timeout)
            s = self.sock.recv(size)
            return s

        except socket.timeout:
            raise ReadTimeout('read timeout %s:%s' % (self.host, self.port))

    def recv(self):

        while True:
            s = self.process()
            if s is None:
                return b''
            elif s == b'':
                #处理ticket数据会返回''
                pass
            elif len(s) > 0:
                return s

    def process(self):
        #只返回应用层数据

        length = 5
        recv_len = length

        head_flowtext = b''
        while len(head_flowtext) < length:
            s = self.mutable_recv(recv_len)
            if not s:
                return None

            head_flowtext += s
            recv_len = length - len(head_flowtext)

        handshake_type = struct.unpack('!B', head_flowtext[:1])[0]
        length = struct.unpack('!H', head_flowtext[3:5])[0]
        flowtext = head_flowtext[5:5 + length]

        recv_len = length
        while len(flowtext) < length:
            s = self.mutable_recv(recv_len)
            if not s:
                return None

            flowtext += s
            recv_len = length - len(flowtext)

        if handshake_type == 0x17:
            if self.tls13:
                p = self.tls_cxt.decrypt(flowtext, b'\x17')
                p, t = p[:-1], p[-1]
                if t == 22:
                    # ticket session
                    pass

                elif t == 23:
                    self.plaintext_reader += p
            else:
                p = self.tls_cxt.decrypt(flowtext, b'\x17')
                self.plaintext_reader += p

        elif handshake_type == 0x15:
            #\x01\x00
            # Level: Warning (1)
            # Description: Close Notify (0)
            self.isclosed = True
            p = self.tls_cxt.decrypt(flowtext, b'\x15')
            raise ConnectionClosed('server closed connect')

        b = self.plaintext_reader
        self.plaintext_reader = b''
        return b