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
import random
import asyncio
import os
import socket
import threading

from pyhttpx.layers.tls.keyexchange import ServerContext, ClientCpiherSpec, ClientKeyExchange
from pyhttpx.layers.tls.handshake import HelloClient
from pyhttpx.layers.tls.suites import CipherSuites
from pyhttpx.layers.tls.extensions import dump_extension

from pyhttpx.layers.tls.tls_context import TLSSessionCtx


from pyhttpx.exception import (
    TLSDecryptErrorExpetion,
    ConnectionTimeout,
    ConnectionClosed,
    ReadTimeout,
)

from pyhttpx.layers.tls.socks import SocketProxy
from pyhttpx.utils import vprint


class TLSSocket:
    def __init__(self, sock=None, server_hostname=None, proxies=None, timeout=None, ssl=None):
        super().__init__()
        self._closed = True
        self._timeout = 0
        self.server_hostname = server_hostname
        self.proxies = proxies
        self._timeout = timeout
        self.sock = sock
        self.context = ssl or default_context()

    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)

    async def connect(self, addres):
        self.servercontext = ServerContext()
        self.tls_cxt = TLSSessionCtx()
        self.context.group_x25519_key = self.tls_cxt.group_x25519_key
        self.context.group_secp_key = self.tls_cxt.group_secp_key
        self.tls_cxt.handshake_data = []
        self.host, self.port = addres[0], int(addres[1])

        self._timeout = self._timeout or 0

        await self._tls_do_handshake()
        self.isclosed = False

    async def _tls_do_handshake(self):

        ciphersuites, extensions =CipherSuites(self.context).dump(),dump_extension(self.host,self.context)
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
                recv = await self.reader.read(8191)

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

    async def recv(self, size=4096):

        s = await self.reader.read(size)
        if not s:
            return None

        s = self.cache + s
        self.cache = b''

        # 会存在读取长度不足而返回空字符,而不是收到fin
        exc_alert = False
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
                exc_alert = True
                raise ConnectionClosed('server closed')

        b = self.plaintext_reader
        self.plaintext_reader = b''
        if exc_alert:
            b = None
        return b



PROTOCOL_TLSv1_2 = b'\x03\x03'
def default_context():
    return SSLContext(PROTOCOL_TLSv1_2)


class SSLContext:
    def __init__(self, protocol=None, http2=False):
        self.protocol = protocol
        self.check_hostname: bool = False
        self.browser_type = 'chrome'
        self.http2 = http2
        self.ciphers = None
        self.exts = None
        self.exts_payload = None
        self.supported_groups = None
        self.ec_points = None
        self.tls_max = 3

    def set_payload(self, browser_type=None,
                    ja3=None,
                    exts_payload=None,
                    shuffle_extension_protocol=None):
        self.browser_type = browser_type or 'chrome'
        self.exts_payload = exts_payload
        self.shuffle_extension_protocol = shuffle_extension_protocol
        #https://www.rfc-editor.org/rfc/rfc8701
        grease_list = [
            0x0A0A, 0x1A1A,
            0x2A2A, 0x3A3A,
            0x4A4A, 0x5A5A,
            0x6A6A, 0x7A7A,
            0x8A8A, 0x9A9A,
            0xAAAA, 0xBABA,
            0xCACA, 0xDADA,
            0xEAEA, 0xFAFA,
        ]
        def choose_grease():

            e = random.choice(grease_list)
            grease_list.remove(e)
            return e


        if ja3:
            self.ja3 = ja3
            if self.browser_type == 'chrome':
                #规范ja3
                tmp = self.ja3.split(',')
                self.grease_group = int(tmp[3].split('-')[0])
                supported_groups = [23,24,25,29,256,257]

                if self.grease_group in supported_groups:
                    self.grease_group = choose_grease()
                    tmp[3] = f'{self.grease_group}-{tmp[3]}'
                self.ja3 = ','.join(tmp)


        else:
            if self.browser_type == 'chrome':

                grease_ciphers = choose_grease()
                grease_ext1 = choose_grease()
                grease_ext2 = choose_grease()
                self.grease_group = choose_grease()
                exts = [grease_ext1,65281,18,27,43,0,5,51,13,11,17513,35,45,23,16,10,grease_ext2,21]
                if self.shuffle_extension_protocol:
                    random.shuffle(exts)

                exts = '-'.join(map(lambda x:str(x), exts))
                self.ja3 = f"771,{grease_ciphers}-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,{exts},{self.grease_group}-29-23-24,0"
                self.exts_payload = {grease_ext2: b'\x00'}


            else:
                #firefox_j,a3
                exts=[0,23,65281,10,11,35,16,5,34,51,43,13,45,28,21]
                if self.shuffle_extension_protocol:
                    random.shuffle(exts)
                exts = '-'.join(map(lambda x:str(x), exts))
                self.ja3 = f"771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,{exts},29-23-24-25-256-257,0"


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













