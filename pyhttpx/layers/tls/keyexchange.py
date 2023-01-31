import struct
import hashlib
import rsa
import OpenSSL

from pyhttpx.layers.tls.crypto.prf import prf
from pyhttpx.layers.tls.suites import TLS_SUITES

from pyhttpx.exception import (TLSECCNotSupportedErrorExpetion,
                                  TLSCipherNotSupportedErrorExpetion)



class ServerStore:
    def __init__(self):
        self.ext = {}
    def load(self,flowtext):

        self.random = flowtext[6:6+32]
        #sessionid长度
        sl = struct.unpack('!B',flowtext[38:39])[0]

        flowtext = flowtext[39:]
        self.sessionId = flowtext[0:sl]
        flowtext = flowtext[sl:]
        self.cipher_suit = flowtext[:2]
        cipher_suit = TLS_SUITES.get(int(self.cipher_suit.hex(), 16))


        if cipher_suit is None:
            raise TLSCipherNotSupportedErrorExpetion(f'negotiation error, the cipher suite does not support {self.cipher_suit.hex()}')

        self.cipher_name = TLS_SUITES.get(int(self.cipher_suit.hex(), 16))['name']
        ext_len = struct.unpack('!H',flowtext[3:5])[0]

        ext_datas = flowtext[5:5+ext_len]

        while ext_datas:
            ext_type = int(ext_datas[:2].hex(), 16)
            el = struct.unpack('!H',ext_datas[2:4])[0]
            val = ext_datas[4:4+el]
            self.ext[ext_type] = val
            ext_datas = ext_datas[4+el:]

        return self

class CertificateContext:
    rsa_pulicKey = None
    def load(self,flowtext, serverstore):
        first_cer_length = b'\x00' + flowtext[7:10]
        first_cer_length = struct.unpack('!I',first_cer_length)[0]
        cert = flowtext[10:10 + first_cer_length]

        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

        if serverstore.cipher_name.startswith('TLS_RSA'):
            self.publickey_bytes = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.cert.get_pubkey())
            self.rsa_pulicKey = rsa.PublicKey.load_pkcs1_openssl_pem(self.publickey_bytes)

        return self

class ServerContext:

    def __init__(self):
        self.done = False
        self.random = None
        self.sessionId = None
        self.curve_name = None
        self.serverpubkey = None


    def load(self, flowtext):
        handshake_type = struct.unpack('!B',flowtext[:1])[0]
        if handshake_type == 0x02:
            #server hello

            self.serverstore = ServerStore().load(flowtext)
        elif handshake_type == 0x0b:
            self.certificatecontext= CertificateContext().load(flowtext,self.serverstore)
        elif handshake_type == 0x0c:
            self.curve_name = flowtext[5:7]
            if not self.curve_name in [b'\x00\x1d',b'\x00\x17',b'\x00\x18',b'\x00\x19']:

                raise TLSECCNotSupportedErrorExpetion(f'不支持椭圆曲线算法: {self.curve_name}')

            if self.curve_name == b'\x00\x1d':
                # x25519
                self.serverpubkey = flowtext[8:8+32]
            elif self.curve_name == b'\x00\x17':
                #secp256r1
                self.serverpubkey = flowtext[8:8 + 65]

            elif self.curve_name == b'\x00\x18':
                #secp384r1
                self.serverpubkey = flowtext[8:8 + 97]
            elif self.curve_name == b'\x00\x19':
                #secp521r1
                self.serverpubkey = flowtext[8:8 + 133]

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
        if len(self.premaster) < 128:
            premaster = struct.pack('!B',len(self.premaster)) + self.premaster
            handshake_type = b'\x10'
            length = struct.pack('!I',len(premaster))[1:]
        else:
            #rsa
            premaster = struct.pack('!H',len(self.premaster)) + self.premaster
            handshake_type = b'\x10'
            length = struct.pack('!I',len(premaster))[1:]
        return b'%s%s%s' % (handshake_type, length, premaster)

    def dump(self,sc):
        handshake = self.handshake()
        sc.handshake_data.append(handshake)
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
    def load(self, premaster, client, server,sc):
        self.premaster = premaster
        self.client = client
        self.server = server
        self.sc = sc
        self.init()

        return self
    def init(self):

        cipher_suit = TLS_SUITES.get(int(self.server.cipher_suit.hex(), 16))

        key_len = cipher_suit['key_len']
        cipher_type = cipher_suit['type']
        #fixed_iv_len = cipher_suit['fixed_iv_len']
        self.hash_name = cipher_suit['sha']
        self.master_secret()
        self.key_expandsion()

        if cipher_type == 'aead':
            self.client_write_key = self.keyBlock[:key_len]
            self.server_write_key = self.keyBlock[key_len:key_len*2]
            self.client_fixed_iv = self.keyBlock[key_len*2:key_len*2+4]
            self.server_fixed_iv = self.keyBlock[key_len*2+4:key_len*2+8]

        elif cipher_type == 'block':

            self.client_mac_key = self.keyBlock[:cipher_suit['mac_key_len']]
            self.server_mac_key = self.keyBlock[cipher_suit['mac_key_len']:cipher_suit['mac_key_len'] * 2]
            self.client_write_key = self.keyBlock[cipher_suit['mac_key_len'] * 2:cipher_suit['mac_key_len'] * 2 + key_len]
            self.server_write_key = self.keyBlock[cipher_suit['mac_key_len'] * 2 + key_len:cipher_suit['mac_key_len'] * 2 + key_len * 2]

    def master_secret(self):
        label = b'master secret'

        seed = label + self.client.random + self.server.random
        #serverhello包含extended master secret
        if self.hash_name == 'sha256':
            self.hashes = hashlib.sha256
        else:
            self.hashes = hashlib.sha384
        if 23 in self.server.ext.keys():
            label = b'extended master secret'

            seed = label + self.hashes(b''.join(self.sc.handshake_data)).digest()

        self.masterSecret = prf(self.premaster, seed,self.hashes, outlen=48)

    def key_expandsion(self):
        seed = b'key expansion' + self.server.random + self.client.random
        self.keyBlock = prf(self.masterSecret, seed, self.hashes,outlen=256)

