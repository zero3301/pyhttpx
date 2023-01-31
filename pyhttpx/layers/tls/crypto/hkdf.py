'''
tls1.3 key expand
rfc5705
'''

import hashlib
import hmac
from math import ceil
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.hashes import Hash,SHA256,SHA384
from cryptography.hazmat.primitives.hmac import HMAC
import struct

from pyhttpx.utils import vprint


#psk pre share key 预共享密钥
#prk 伪随机密钥
#imk 输入材料密钥

class TLS13_HKDF(object):
    def __init__(self, hash_name="SHA256"):
        if hash_name == "SHA256":
            self.hash = SHA256()
            self.key_len = 16
        else:
            self.hash = SHA384()
            self.key_len = 32


    def extract(self, salt=None, ikm=None):
        h = self.hash
        hkdf = HKDF(h, h.digest_size, salt, None, default_backend())
        if ikm is None:
            ikm = b"\x00" * h.digest_size
        return hkdf._extract(ikm)

    def expand(self, prk, label, L):

        h = self.hash
        hkdf = HKDFExpand(h, L, label, default_backend())
        return hkdf.derive(prk)

    def expand_label(self, secret, label, hash_value, length):
        hkdf_label = struct.pack("!H", length)

        hkdf_label += struct.pack("B", 6+len(label))
        hkdf_label += b"tls13 "
        #TLS 1.3, tls13
        hkdf_label += label
        hkdf_label += struct.pack("B", len(hash_value))
        hkdf_label += hash_value
        return self.expand(secret, hkdf_label, length)

    def derive_secret(self, secret, label, messages):
        h = Hash(self.hash, backend=default_backend())
        h.update(messages)
        hash_messages = h.finalize()
        hash_len = self.hash.digest_size
        return self.expand_label(secret, label, hash_messages, hash_len)

    def compute_verify_data(self, basekey, handshake_context):
        hash_len = self.hash.digest_size
        finished_key = self.expand_label(basekey, b"finished", b"", hash_len)
        h = Hash(self.hash, backend=default_backend())
        h.update(handshake_context)
        hash_value = h.finalize()
        hm = HMAC(finished_key, self.hash, default_backend())
        hm.update(hash_value)
        return hm.finalize()


    def make_secret(self,tls13_dhe_secret,handshake_messages):
        salt = None
        tls13_psk_secret = None
        tls13_early_secret = self.extract(salt, tls13_psk_secret)
        secret = self.derive_secret(tls13_early_secret, b"derived", b"")

        tls13_handshake_secret = self.extract(secret, tls13_dhe_secret)

        client_handshake_traffic_secret = self.derive_secret(tls13_handshake_secret,
                                                             b"c hs traffic",
                                                             b"".join(handshake_messages))

        server_handshake_traffic_secret = self.derive_secret(tls13_handshake_secret,
                                                             b"s hs traffic",
                                                             b"".join(handshake_messages))

        # traffic
        client_handshake_write_key = self.expand_label(client_handshake_traffic_secret, b"key", b"", self.key_len)
        client_handshake_write_iv = self.expand_label(client_handshake_traffic_secret, b"iv", b"", 12)
        server_handshake_write_key = self.expand_label(server_handshake_traffic_secret, b"key", b"", self.key_len)
        server_handshake_write_iv = self.expand_label(server_handshake_traffic_secret, b"iv", b"", 12)


        vprint('handshake')
        vprint('client_handshake_write_key = ', client_handshake_write_key)
        vprint('client_handshake_write_iv = ', client_handshake_write_iv)
        vprint('server_handshake_write_key = ',server_handshake_write_key)
        vprint('server_handshake_write_iv = ', server_handshake_write_iv)

        tmp = self.derive_secret(tls13_handshake_secret, b"derived", b"")
        tls13_master_secret = self.extract(tmp, None)
        client_application_traffic_secret = self.derive_secret(tls13_master_secret, b"c ap traffic",
                                                               b"".join(handshake_messages))
        server_application_traffic_secret = self.derive_secret(tls13_master_secret, b"s ap traffic",
                                                               b"".join(handshake_messages))
        client_application_write_key = self.expand_label(client_application_traffic_secret,b"key",b"",self.key_len)
        client_application_write_iv = self.expand_label(client_application_traffic_secret,b"iv",b"",12)

        server_application_write_key = self.expand_label(server_application_traffic_secret,b"key",b"",self.key_len)
        server_application_write_iv = self.expand_label(server_application_traffic_secret,b"iv",b"",12)

        vprint('app_write')
        secrets = {}
        vprint('server_application_write_key = ',server_application_write_key)
        vprint('server_application_write_iv = ',server_application_write_iv)

        secrets['tls13_master_secret'] = tls13_master_secret
        secrets['client_handshake_traffic_secret'] = client_handshake_traffic_secret
        secrets['server_handshake_traffic_secret'] = server_handshake_traffic_secret
        secrets['client_application_traffic_secret'] = client_application_traffic_secret
        secrets['server_application_traffic_secret'] = server_application_traffic_secret
        secrets['client_handshake_write_key'] = client_handshake_write_key
        secrets['client_handshake_write_iv'] = client_handshake_write_iv
        secrets['server_handshake_write_key'] = server_handshake_write_key
        secrets['server_handshake_write_iv'] = server_handshake_write_iv
        secrets['server_application_write_key'] = server_application_write_key
        secrets['server_application_write_iv'] = server_application_write_iv
        secrets['client_application_write_key'] = client_application_write_key
        secrets['client_application_write_iv'] = client_application_write_iv

        return secrets



if __name__ == '__main__':
    hash_name = 'SHA256'
    hkdf = TLS13_HKDF(hash_name)
    secrets = {}
    handshake_messages = []
