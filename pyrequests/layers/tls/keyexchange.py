import struct
from pyrequests.layers.tls.crypto.prf import prf


class SessionContext:
    def __init__(self):
        self.verify_data = []
class ServerStore:
    def load(self,flowtext):
        self.random = flowtext[6:6+32]
        self.sessionId = flowtext[39:39+32]
        return self

class CertificateContext:
    def load(self,flowtext):
        first_cer_length = b'\x00' + flowtext[7:10]
        first_cer_length = struct.unpack('!I',first_cer_length)[0]
        cert = flowtext[10:10 + first_cer_length]

        #self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        #print('取消证书验证')
        #pulicKey = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.cert.get_pubkey())
        #self.rsa_pulicKey = rsa.PublicKey.load_pkcs1_openssl_pem(pulicKey)
        return self

class ServerContext:

    def __init__(self):
        self.done = False
        self.random = None
        self.sessionId = None

    def load(self,flowtext):
        handshake_type = struct.unpack('!B',flowtext[:1])[0]
        if handshake_type == 0x02:
            #server hello
            self.serverstore = ServerStore().load(flowtext)
        elif handshake_type == 0x0b:
            self.certificatecontext= CertificateContext().load(flowtext)
        elif handshake_type == 0x0c:
            #x25519
            #self.serverpubkey = flowtext[8:8+32]
            #secp256r1
            self.serverpubkey = flowtext[8:8 + 65]
            #print('*** 注意ECDHE公钥是否正确 = ', self.serverpubkey.hex())

        elif handshake_type == 0x0e:

            self.done = True


        return self

class ClientKeyExchange:
    def __init__(self, premaster):
        self.content_type = b'\x16'
        self.version = b'\x03\x03'
        self.premaster = premaster

    def handshake(self):
        premaster = struct.pack('!B',len(self.premaster)) + self.premaster
        handshake_type = b'\x10'
        length = struct.pack('!I',len(premaster))[1:]

        return b'%s%s%s' % (handshake_type, length, premaster)

    def dump(self,sc):
        handshake = self.handshake()
        sc.verify_data.append(handshake)
        return self.content_type + self.version + struct.pack('!H',len(handshake))+ handshake

class ClientCpiherSpec:
    def __init__(self):
        self.content_type = b'\x14'
        self.version = b'\x03\x03'
        self.body = b'\x01'
    def dump(self):
        length = struct.pack('!H', len(self.body))
        return b'%s%s%s%s' % (self.content_type, self.version, length, self.body)

class KeyStore():
    def load(self, premaster, client, server):
        self.premaster = premaster
        self.client = client
        self.server = server
        self.init()

        return self
    def init(self):

        self.master_secret()
        self.key_expandsion()
        #256
        self.client_write_key = self.keyBlock[:16]
        self.server_write_key = self.keyBlock[16:32]
        self.client_fixed_iv = self.keyBlock[32:36]
        self.server_fixed_iv = self.keyBlock[36:40]
        #384
        # self.client_write_key = self.keyBlock[:32]
        # self.server_write_key = self.keyBlock[32:64]
        # self.client_fixed_iv = self.keyBlock[64:68]
        # self.server_fixed_iv = self.keyBlock[68:72]

    def master_secret(self):
        label = b'master secret'
        #label = b'extended master secret'
        seed = label + self.client.random + self.server.random

        #seed = label + hashlib.sha256(b''.join(verify_data)).digest()
        self.masterSecret = prf(self.premaster, seed, outlen=48)

    def key_expandsion(self):
        seed = b'key expansion' + self.server.random + self.client.random
        self.keyBlock = prf(self.masterSecret, seed, outlen=128)



