
"""
TLS session handler.
"""

import socket
import struct
import hashlib
from copy import deepcopy
import gzip
import time
import warnings



from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


from pyrequests.layers.tls.keyexchange import SessionContext,ServerContext,ClientCpiherSpec,ClientKeyExchange,KeyStore
from pyrequests.layers.tls.handshake import HelloClient
from pyrequests.layers.tls.suites import CipherSuites
from pyrequests.layers.tls.extensions import dump_extension

from pyrequests.layers.tls.crypto.prf import prf
from pyrequests.layers.tls.crypto.aes import AES_GCM
from pyrequests.layers.tls.crypto.ecc import CryptoContextFactory

from pyrequests.models import Response



# expire_stamp = 1657074207
# if time.time() -expire_stamp > 7*24*3600:
#     raise BaseException('很抱歉,测试版本已到期,详情到项目地址: https://github.com/zero3301/pyrequests')


class TlsSession():
    def __init__(self, ja3=None,**kwargs):
        self.sc = SessionContext()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servercontext = ServerContext()
        self.ja3 = ja3
        self._closed = True


    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)


    def connect(self, host, port):
        self.sc.verify_data = []
        self.host, self.port = host, port
        self.t1 = time.time()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)


        #recv超时设置
        #self.socket.settimeout()

        try:
            self.socket.connect((host, port))
        except ConnectionRefusedError:

            raise ConnectionError('无法连接 %s' % self.host)

        else:
            self.local_ip, self.local_port = self.socket.getsockname()[:2]
            self.remote_ip, self.remote_port = self.socket.getpeername()[:2]


            #print('客户端地址: %s:%s' % (self.local_ip, self.port))
            #print('服务器地址: %s:%s' % (self.remote_ip, self.remote_port))
            self.isclosed = False

            return self._tls_do_handshake()


    def _tls_do_handshake(self):

        ciphersuites, extensions = CipherSuites().dump(),dump_extension(self.host,ja3=self.ja3)
        hello = HelloClient(ciphersuites, extensions)
        self.socket.send(hello.dump(self.sc))


        self.client_seq = 0
        self.server_seq = 0

        exchanage  = True
        cache =b''

        while True:
            recv = self.socket.recv(8126)
            recv = cache + recv
            cache = b''
            if recv:
                while recv:

                    handshake_type = struct.unpack('!B', recv[:1])[0]
                    length = struct.unpack('!H', recv[3:5])[0]
                    flowtext = recv[5:5 + length]

                    if len(flowtext) != length:
                        cache = deepcopy(recv[:])
                        break

                    if handshake_type == 0x16:
                        self.sc.verify_data.append(flowtext)
                        self.servercontext.load(flowtext)

                    elif handshake_type == 0x14:
                        self.server_seq +=1
                        #print('握手完成')
                        return True
                    #warnings.warn('fail')
                    elif handshake_type == 0x15:


                        warnings.warn('握手失败,Description: Decrypt Error (%s)' % flowtext)
                        raise ConnectionError('handshake failed')
                    recv = recv[5+length:]

                if self.servercontext.done and exchanage:

                    # publickey_bytes = CryptoContextFactory.crypto_container['x25519'].client_kx_privkey.public_key().public_bytes(
                    #     serialization.Encoding.Raw,
                    #     serialization.PublicFormat.Raw
                    # )
                    # pms = CryptoContextFactory.crypto_container['x25519'].client_kx_privkey.exchange(
                    #     x25519.X25519PublicKey.from_public_bytes(servercontext.serverpubkey))

                    from cryptography.hazmat.primitives.asymmetric import ec as cg_ec
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import serialization, hashes

                    client_kx_privkey = CryptoContextFactory.crypto_container['secp256r1'].client_kx_privkey

                    server_publickey = cg_ec.EllipticCurvePublicKey.from_encoded_point(
                        cg_ec.SECP256R1(),
                        self.servercontext.serverpubkey
                    )
                    pms = client_kx_privkey.exchange(cg_ec.ECDH(), server_publickey)


                    publickey_bytes = client_kx_privkey.public_key().public_bytes(
                        serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint
                    )

                    keychange = ClientKeyExchange(publickey_bytes).dump(self.sc)
                    changecipherspec =  ClientCpiherSpec().dump()


                    self.keystore = KeyStore().load(pms, hello.hanshake, self.servercontext.serverstore)
                    explicit_nonce = struct.pack('!Q',self.client_seq)

                    nonce = self.keystore.client_fixed_iv +  explicit_nonce
                    handshake = hashlib.sha256(b''.join(self.sc.verify_data)).digest()
                    label = b"client finished"
                    for i in self.sc.verify_data:
                        #print(i.hex())
                        pass

                    self.sc.verify_data = []
                    plaintext = prf(self.keystore.masterSecret, label + handshake, outlen=12)

                    plaintext = b'\x14\x00\x00\x0c' + plaintext
                    # 附加数据
                    aead = explicit_nonce + b'\x16\x03\x03' + struct.pack('!H', len(plaintext))
                    aes = AES_GCM()

                    ciphertext, tag = aes.aes_encrypt(self.keystore.client_write_key, nonce, aead, plaintext)
                    ciphertext = explicit_nonce + ciphertext + tag

                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext )) + ciphertext
                    #self.socket.send(encrypted_message)
                    self.socket.send(keychange + changecipherspec + encrypted_message)
                    self.client_seq += 1
                    exchanage = False



    def send(self, plaintext):

        #print('tlssession send', plaintext)
        self.response = Response(tls_ctx=self)
        explicit_nonce = struct.pack('!Q', self.client_seq)
        nonce = self.keystore.client_fixed_iv + explicit_nonce

        # 附加数据
        aead = explicit_nonce + b'\x17\x03\x03' + struct.pack('!H', len(plaintext))
        aes = AES_GCM()

        ciphertext, tag = aes.aes_encrypt(self.keystore.client_write_key, nonce, aead, plaintext)
        ciphertext = explicit_nonce + ciphertext + tag
        encrypted_message = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
        self.socket.send(encrypted_message)
        self.client_seq += 1
        self.plaintext_buffer_reader = []
        cache = b''

        while True:
            recv = self.socket.recv(6324)

            if not recv:
                # 服务器不保持长连接,传输完毕断开连接
                print('收到fin包')
                return

            recv = cache + recv

            cache = b''


            while recv and len(recv) >=5:
                handshake_type = struct.unpack('!B', recv[:1])[0]
                length = struct.unpack('!H', recv[3:5])[0]
                flowtext = recv[5:5 + length]
                if len(flowtext) != length:
                    cache = deepcopy(recv[:])
                    break


                if handshake_type == 0x17:
                    ciphertext = flowtext

                    explicit_nonce = struct.pack('!Q', self.server_seq)
                    nonce = self.keystore.server_fixed_iv + ciphertext[:8]

                    # 附加数据
                    aead = explicit_nonce + b'\x17\x03\x03' + struct.pack('!H', len(ciphertext) - 24)
                    aes = AES_GCM()
                    # print('nonce = ',nonce)
                    # print('aead', aead)
                    explicit_nonce, ciphertext, tag = ciphertext[:8], ciphertext[8:-16], ciphertext[-16:]
                    plaintext = aes.aes_decrypt(self.keystore.server_write_key, nonce, aead, ciphertext, tag)
                    self.server_seq += 1

                    self.response.flush(plaintext)
                    if self.response.read_ended:
                        return True


                elif handshake_type == 0x15:


                    return  False

                recv = recv[5 + length:]

