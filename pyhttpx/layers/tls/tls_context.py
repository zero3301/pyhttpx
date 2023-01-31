import time
from collections import namedtuple
import hashlib
import struct
import os

import hmac

import rsa
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ec as cg_ec
from cryptography.hazmat.primitives import serialization

from pyhttpx.layers.tls.crypto.ecc import CryptoContextFactory
from pyhttpx.layers.tls.crypto.prf import prf
from pyhttpx.layers.tls.suites import (
    get_algs_from_ciphersuite_name,
    TLS_SUITES
)
from pyhttpx.layers.tls.crypto.hkdf import TLS13_HKDF
from pyhttpx.exception import TLSVerifyDataExpetion

import threading

class TLSContext(object):

    def __init__(self, name):
        self.name = name
        self.handshake = None
        self.sequence = 0
        self.nonce = 0
        self.random = None
        self.session_id = None
        self.crypto_alg = None
        self.compression = None
        self.finished_secret = None
        self.finished_hashes = []
        self.shares = []
        self.sym_keystore_history = []
        self.must_encrypt = False

    

def rsa_encrypt(plaintxt, publickey):
    return rsa.encrypt(plaintxt, publickey)

class TLSSessionCtx(object):

    def __init__(self, client=True):
        self.client = client
        self.server = not self.client
        self.client_ctx = TLSContext("Client TLS context")
        self.server_ctx = TLSContext("Server TLS context")
        self.certificate_request = False
        self.negotiated = namedtuple("negotiated", ["ciphersuite", "key_exchange", "encryption", "mac", "compression",
                                                    "compression_algo", "version", "sig", "resumption"])
        self.negotiated.ciphersuite = None
        self.negotiated.key_exchange = None
        self.negotiated.encryption = None
        self.negotiated.mac = None
        
        self.negotiated.version = None
        self.negotiated.hashes = None
        self.negotiated.resumption = False

        self.ticket = None
        self.encrypted_premaster_secret = None
        self.premaster_secret = None
        self.master_secret = None

        self.extended_master_secret = False

        self.client_mac_key = None
        self.server_mac_key = None

        self.client_write_key = None
        self.server_write_key = None
        self.client_fixed_iv = None
        self.server_fixed_iv = None
        self.curve_name = None
        self.server_ecdhe_pubkey = None
        self.handshake_data = []
        self.tls13 = False

        self.tls_version = b'\x03\x03'
        name_curve = 0x001d
        self.group_x25519_key = CryptoContextFactory.crypto_container[
            name_curve].client_kx_privkey.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

        self.client_secp_kx_privkey = CryptoContextFactory.crypto_container[0x0017].client_kx_privkey
        self.group_secp_key = self.client_secp_kx_privkey.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )

        self.hkdf = TLS13_HKDF('sha256')

    def encrypt(self, P, content_type):
        sequence = struct.pack('!Q', self.client_ctx.sequence)

        # 附加数据
        # 记录层随机数 + b'\x16\x03\x03' + len(plaintext)
        if self.tls13:
            A = content_type + b'\x03\x03' + struct.pack('!H', len(P) + 16)
        else:
            A = sequence + content_type + self.tls_version + struct.pack('!H', len(P))
        if self.cls_cipher_alg.type == 'block':

            tbd = struct.pack('!Q', self.client_ctx.sequence) + content_type + self.tls_version + struct.pack('!H', len(
                P)) + P
            mac = hmac.new(self.client_mac_key, tbd, hashlib.sha1).digest()
            P = P + mac
            P = os.urandom(16) + P


        data = self.client_ctx.crypto_alg.encrypt(P, A, sequence)
        self.client_ctx.sequence += 1
        return data

    def decrypt(self, C,content_type ):

        sequence = struct.pack('!Q', self.server_ctx.sequence)
        if self.tls13:
            #rfc8446
            # 密文已经包含tag的长度
            A = content_type + b'\x03\x03' + struct.pack('!H', len(C))
        else:
            p_len = len(C) - self.cls_cipher_alg.nonce_explicit_len - self.cls_cipher_alg.tag_len
            A = sequence + content_type + b'\x03\x03' + struct.pack('!H', p_len)
        data = self.server_ctx.crypto_alg.decrypt(C, A, sequence)
        self.server_ctx.sequence += 1
        return data
    
    def load_alg(self):
        cipher_name = TLS_SUITES.get(self.negotiated.ciphersuite)['name']
        kx_alg, cipher_alg, hmac_alg, hash_alg, tls1_3 = get_algs_from_ciphersuite_name(cipher_name)

        if hash_alg == 'SHA384':
            self.hash_alg = hashlib.sha384
        else:
            self.hash_alg = hashlib.sha256

        if hmac_alg == 'HMAC-SHA':
            self.hmac_alg = hashlib.sha1

        elif hmac_alg == 'HMAC-SHA256':
            self.hmac_alg = hashlib.sha256

        if self.tls13:
            #hash_name = 'SHA256'

            self.hkdf = TLS13_HKDF(hash_alg)
            if 'CHACHA20_POLY1305' in cipher_name:
                self.hkdf.key_len = 32


        self.cls_cipher_alg = cipher_alg
        self.kx_alg = kx_alg
        self.hmac_alg = hmac_alg
        self.negotiated_premaster_secret()

    def load_key(self):
        key_len = self.cls_cipher_alg.key_len
        cipher_type = self.cls_cipher_alg.type
        fixed_iv_len = self.cls_cipher_alg.fixed_iv_len
        mac_key_len = self.cls_cipher_alg.mac_key_len

        self.make_master_secret()
        self.key_expandsion()

        if cipher_type == 'aead':
            self.client_write_key = self.key_block[:key_len]
            self.server_write_key = self.key_block[key_len:key_len * 2]
            self.client_fixed_iv = self.key_block[key_len * 2:key_len * 2 + fixed_iv_len]
            self.server_fixed_iv = self.key_block[key_len * 2 + fixed_iv_len:key_len * 2 + fixed_iv_len * 2]

        elif cipher_type == 'block':
            self.client_mac_key = self.key_block[:mac_key_len]
            self.server_mac_key = self.key_block[mac_key_len:mac_key_len * 2]
            self.client_write_key = self.key_block[mac_key_len * 2:mac_key_len * 2 + key_len]
            self.server_write_key = self.key_block[mac_key_len * 2 + key_len:mac_key_len * 2 + key_len * 2]

        self.client_ctx.crypto_alg = self.cls_cipher_alg(self.client_write_key, self.client_fixed_iv)
        self.server_ctx.crypto_alg = self.cls_cipher_alg(self.server_write_key, self.server_fixed_iv)

    def make_master_secret(self):
        label = b'master secret'
        seed = label + self.client_ctx.random + self.server_ctx.random
        # serverhello包含extended master secret
        if self.extended_master_secret:
            label = b'extended master secret'
            seed = label + self.hash_alg(b''.join(self.handshake_data)).digest()


        self.master_secret = prf(self.premaster_secret, seed, self.hash_alg, outlen=48)
        sslkey_file_name = os.environ.get('SSLKEYLOGFILE')
        if sslkey_file_name:
            with open(sslkey_file_name, 'a') as f:
                s = f'CLIENT_RANDOM {self.client_ctx.random.hex()} {self.master_secret.hex()}'
                f.write(s)

    def key_expandsion(self):
        seed = b'key expansion' + self.server_ctx.random + self.client_ctx.random
        self.key_block = prf(self.master_secret, seed, self.hash_alg, outlen=256)


    def negotiated_premaster_secret(self):

        if self.kx_alg.startswith('ECDHE'):
            name_curve = struct.unpack('!H',self.curve_name)[0]
            if name_curve == 0x001d:

                self.publickey_bytes = CryptoContextFactory.crypto_container[name_curve].client_kx_privkey.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw
                )
                self.premaster_secret = CryptoContextFactory.crypto_container[name_curve].client_kx_privkey.exchange(
                    x25519.X25519PublicKey.from_public_bytes(self.server_ecdhe_pubkey))
            else:

                client_kx_privkey = CryptoContextFactory.crypto_container[name_curve].client_kx_privkey
                server_publickey = cg_ec.EllipticCurvePublicKey.from_encoded_point(

                    CryptoContextFactory.crypto_container[name_curve].curve,
                    self.server_ecdhe_pubkey
                )
                self.publickey_bytes = client_kx_privkey.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint
                )
                self.premaster_secret = client_kx_privkey.exchange(cg_ec.ECDH(), server_publickey)


        elif self.kx_alg.startswith('RSA'):
            self.premaster_secret = b'\x03\x03' + os.urandom(46)
            self.publickey_bytes = rsa_encrypt(self.premaster_secret, self.rsa_pulicKey)

    def get_verify_data(self, data=None):
        #对于cbc-sha,tls1.2中,hmac采用sha1,消息摘要用sha256

        handshake = self.hash_alg(b''.join(self.handshake_data)).digest()
        label = b"client finished"
        plaintext = prf(self.master_secret, label + handshake, self.hash_alg, outlen=12)
        verify_data = b'\x14\x00\x00\x0c' + plaintext

        self.handshake_data.append(verify_data)
        return verify_data


    def verify_server_message(self, server_verify_data):

        label = b"server finished"
        handshake = self.hash_alg(b''.join(self.handshake_data)).digest()
        tmp = prf(self.master_secret, label + handshake, self.hash_alg,
                                 outlen=12)

        tmp = b'\x14\x00\x00\x0c' + tmp
        if tmp != server_verify_data:
            raise TLSVerifyDataExpetion('TLSVerifyDataExpetion')


    def compute_verify_data(self):

        verify_data = self.hkdf.compute_verify_data(
            self.secrets['client_handshake_traffic_secret'], b''.join(self.handshake_data))

        # verify_data_len=3byte
        verify_data  = b'\x14' + struct.pack("!I", len(verify_data))[1:] + verify_data + b'\x16'
        return verify_data
    def make_secret(self, server_publickey):


        self.premaster_secret = CryptoContextFactory.crypto_container[
            0x001d].client_kx_privkey.exchange(
            x25519.X25519PublicKey.from_public_bytes(server_publickey))

        self.secrets = self.hkdf.make_secret(self.premaster_secret, self.handshake_data)

        client_handshake_traffic_secret = self.secrets['client_handshake_traffic_secret']
        server_handshake_traffic_secret = self.secrets['server_handshake_traffic_secret']

        sslkey_file_name = os.environ.get('SSLKEYLOGFILE')
        if sslkey_file_name:
            with open(sslkey_file_name, 'a') as f:
                s = f'CLIENT_HANDSHAKE_TRAFFIC_SECRET {self.client_ctx.random.hex()} {client_handshake_traffic_secret.hex()}\n' \
                    f'SERVER_HANDSHAKE_TRAFFIC_SECRET {self.client_ctx.random.hex()} {server_handshake_traffic_secret.hex()}\n' \
                    f'CLIENT_TRAFFIC_SECRET_0 {self.client_ctx.random.hex()} {self.secrets["client_application_traffic_secret"].hex()}\n' \
                    f'SERVER_TRAFFIC_SECRET_0 {self.client_ctx.random.hex()} {self.secrets["server_application_traffic_secret"].hex()}\n'

                f.write(s)


        import time
        #time.sleep(11111)
        self.server_handshake_write_key = self.secrets['server_handshake_write_key']
        self.server_handshake_write_iv = self.secrets['server_handshake_write_iv']
        self.client_handshake_write_key = self.secrets['client_handshake_write_key']
        self.client_handshake_write_iv = self.secrets['client_handshake_write_iv']

        self.tls13_master_secret = self.secrets['tls13_master_secret']



        self.client_ctx.crypto_alg = self.cls_cipher_alg(self.client_handshake_write_key, self.client_handshake_write_iv)
        self.server_ctx.crypto_alg = self.cls_cipher_alg(self.server_handshake_write_key, self.server_handshake_write_iv)

    def derive_application_traffic_secret(self):


        client_application_traffic_secret = self.hkdf.derive_secret(self.tls13_master_secret,
                                                                    b"c ap traffic",
                                                                    b"".join(self.handshake_data))
        server_application_traffic_secret = self.hkdf.derive_secret(self.tls13_master_secret,
                                                                    b"s ap traffic",
                                                                    b"".join(self.handshake_data))

        self.client_application_write_key = self.hkdf.expand_label(client_application_traffic_secret,
                                                                   b"key",
                                                                   b"", self.hkdf.key_len)
        self.client_application_write_iv = self.hkdf.expand_label(client_application_traffic_secret,
                                                                  b"iv",
                                                                  b"", 12)

        self.server_application_write_key = self.hkdf.expand_label(server_application_traffic_secret,
                                                                   b"key",
                                                                   b"", self.hkdf.key_len)
        self.server_application_write_iv = self.hkdf.expand_label(server_application_traffic_secret,
                                                                  b"iv",
                                                                  b"", 12)


class TLSSessionCtx13(TLSSessionCtx):
    def __init__(self, client=True):
        self.client = client
        self.server = not self.client
        self.client_ctx = TLSContext("Client TLS context")
        self.server_ctx = TLSContext("Server TLS context")

        self.negotiated = namedtuple("negotiated", ["ciphersuite", "key_exchange", "encryption", "mac", "compression",
                                                    "compression_algo", "version", "sig", "resumption"])


        self.handshake_data = []

        self.tls_version = b'\x03\x04'

        name_curve = 0x001d
        self.group_x25519_key = CryptoContextFactory.crypto_container[name_curve].client_kx_privkey.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )


        self.client_secp_kx_privkey = CryptoContextFactory.crypto_container[0x0017].client_kx_privkey
        self.group_secp_key =  self.client_secp_kx_privkey.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )
        hash_name = 'sha256'
        self.hkdf = TLS13_HKDF(hash_name)

    def make_secret(self, server_publickey):


        self.premaster_secret = CryptoContextFactory.crypto_container[
            0x001d].client_kx_privkey.exchange(
            x25519.X25519PublicKey.from_public_bytes(server_publickey))

        self.secrets = self.hkdf.make_secret(self.premaster_secret, self.handshake_data)
        self.server_handshake_write_key = self.secrets['server_handshake_write_key']
        self.server_handshake_write_iv = self.secrets['server_handshake_write_iv']
        self.client_handshake_write_key = self.secrets['client_handshake_write_key']
        self.client_handshake_write_iv = self.secrets['client_handshake_write_iv']

        self.tls13_master_secret = self.secrets['tls13_master_secret']



        self.client_ctx.crypto_alg = self.cls_cipher_alg(self.client_handshake_write_key, self.client_handshake_write_iv)
        self.server_ctx.crypto_alg = self.cls_cipher_alg(self.server_handshake_write_key, self.server_handshake_write_iv)

    def derive_application_traffic_secret(self):

        client_application_traffic_secret = self.hkdf.derive_secret(self.tls13_master_secret,
                                                                    b"c ap traffic",
                                                                    b"".join(self.handshake_data))
        server_application_traffic_secret = self.hkdf.derive_secret(self.tls13_master_secret,
                                                                    b"s ap traffic",
                                                                    b"".join(self.handshake_data))

        self.client_application_write_key = self.hkdf.expand_label(client_application_traffic_secret,
                                                                   b"key",
                                                                   b"", self.hkdf.key_len)
        self.client_application_write_iv = self.hkdf.expand_label(client_application_traffic_secret,
                                                                  b"iv",
                                                                  b"", 12)

        self.server_application_write_key = self.hkdf.expand_label(server_application_traffic_secret,
                                                                   b"key",
                                                                   b"", self.hkdf.key_len)
        self.server_application_write_iv = self.hkdf.expand_label(server_application_traffic_secret,
                                                                  b"iv",
                                                                  b"", 12)


    def encrypt(self, P,content_type ):

        sequence = struct.pack('!Q', self.client_ctx.sequence)
        p_len = len(P)

        #content_type + b'\x03\x03' + len(plaintext) + tag_len
        A = content_type + b'\x03\x03' + struct.pack('!H', p_len + 16)
        data = self.client_ctx.crypto_alg.encrypt(P, A, sequence)
        self.client_ctx.sequence += 1
        return data

    def decrypt(self, C,content_type ):

        sequence = struct.pack('!Q', self.server_ctx.sequence)
        p_len = len(C)
        #密文已经包含tag的长度
        A = content_type + b'\x03\x03' + struct.pack('!H', p_len)
        data = self.server_ctx.crypto_alg.decrypt(C, A, sequence)
        self.server_ctx.sequence += 1
        return data


    def load_alg(self):
        cipher_name = TLS_SUITES.get(self.negotiated.ciphersuite)['name']

        kx_alg, cipher_alg, hmac_alg, hash_alg, tls1_3 = get_algs_from_ciphersuite_name(cipher_name)
        self.hash_alg = hashlib.sha256
        from pyhttpx.layers.tls.crypto.cipher_aead import Cipher_AES_128_GCM_TLS13

        self.hmac_alg = hashlib.sha256
        self.cls_cipher_alg = Cipher_AES_128_GCM_TLS13

        self.kx_alg = kx_alg
        self.hmac_alg = hmac_alg


    def compute_verify_data(self):
        verify_data = self.hkdf.compute_verify_data(
            self.secrets['client_handshake_traffic_secret'], b''.join(self.handshake_data))

        #verify_data_len=3byte
        verify_data  = b'\x14' + struct.pack("!I", len(verify_data))[1:] + verify_data + b'\x16'

        return verify_data