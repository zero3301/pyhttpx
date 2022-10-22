

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E501
from cryptography.hazmat.primitives.ciphers.aead import (AESGCM,
                                                             ChaCha20Poly1305)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

_tls_aead_cipher_algs = {}
class _AEADCipherMetaclass(type):
    """
    """
    def __new__(cls, ciph_name, bases, dct):
        if not ciph_name.startswith("_AEADCipher"):
            dct["name"] = ciph_name[7:]     # remove leading "Cipher_"
        the_class = super(_AEADCipherMetaclass, cls).__new__(cls, ciph_name,
                                                             bases, dct)
        if not ciph_name.startswith("_AEADCipher"):
            _tls_aead_cipher_algs[ciph_name[7:]] = the_class
        return the_class

class AEADTagError(Exception):
    """
    Raised when MAC verification fails.
    """
    pass

class _AEADCipher(metaclass=_AEADCipherMetaclass):
    """

    """
    type = "aead"

    def __init__(self, key=None, fixed_iv=None, nonce_explicit=None):

        self.nonce_explicit = nonce_explicit

        #从超类调用,避免死锁

        super(_AEADCipher, self).__setattr__("key", key)
        super(_AEADCipher, self).__setattr__("fixed_iv", fixed_iv)
        super(_AEADCipher, self).__setattr__("nonce_explicit", nonce_explicit)
        if hasattr(self,'cipher_cls'):
            self._cipher = self.cipher_cls(key)


    def __setattr__(self, name, val):

        if name == "key":
            if self._cipher is not None:
                if hasattr(self, "cipher_cls"):
                    self._cipher._key = val
                else:
                    #通过Cipher构建的加密类
                    self._cipher.algorithm.key = val

        super(_AEADCipher, self).__setattr__(name, val)

    def _get_nonce(self):

        if isinstance(self._cipher, ChaCha20Poly1305):
            N = self.get_chacha20_nonce()

        elif self.tls13:
            N = self.get_chacha20_nonce()

        else:
            N = self.fixed_iv + self.nonce_explicit

        return N

    def encrypt(self, P, A, seq_num=None):
        #显示随机数采用序列号,P是明文,A是附加数据,输出密文+mac(消息验证码)
        self.nonce_explicit = seq_num
        N = self._get_nonce()
        C = self._cipher.encrypt(N, P, A)

        return b'%s%s' % (self.nonce_explicit[:self.nonce_explicit_len], C)


    def decrypt(self, C, A, seq_num=None):
        try:
            nonce_explicit, C = C[:self.nonce_explicit_len], C[self.nonce_explicit_len:]
            self.nonce_explicit = nonce_explicit or seq_num
            N = self._get_nonce()
            P = self._cipher.decrypt(N, C, A)


        except InvalidTag:
            raise AEADTagError("<unauthenticated data>")

        return P

    def strxor(self,s1, s2):
        s = bytes(map(lambda x, y: x ^ y, s1, s2))
        return s

    def get_chacha20_nonce(self):
        """
            rfc7905 对于chacha20-poly1305重新计算iv
        """
        padlen = 12 - len(self.nonce_explicit)
        padded_seq_num = b"\x00" * padlen + self.nonce_explicit
        return self.strxor(padded_seq_num, self.fixed_iv)


class Cipher_AES_128_GCM(_AEADCipher):
    tls13 = False
    cipher_cls = AESGCM
    key_len = 16
    tag_len = 16
    nonce_explicit_len = 8
    mac_key_len = 0
    fixed_iv_len = 4
class Cipher_AES_256_GCM(Cipher_AES_128_GCM):
    tls13 = False
    key_len = 32

class Cipher_CHACHA20_POLY1305(_AEADCipher):
    tls13 = False
    cipher_cls = ChaCha20Poly1305
    key_len = 32
    tag_len = 16
    fixed_iv_len = 12
    nonce_explicit_len = 0
    mac_key_len = 0

class Cipher_AES_128_GCM_TLS13(Cipher_AES_128_GCM):
    tls13 = True
    nonce_explicit_len = 0
    fixed_iv_len = 12

class Cipher_AES_256_GCM_TLS13(Cipher_AES_128_GCM):
    tls13 = True
    key_len = 32
    nonce_explicit_len = 0
    fixed_iv_len = 12

class Cipher_CHACHA20_POLY1305_TLS13(_AEADCipher):
    tls13 = True
    cipher_cls = ChaCha20Poly1305
    key_len = 32
    tag_len = 16
    fixed_iv_len = 12
    nonce_explicit_len = 0
    mac_key_len = 0

if __name__ == '__main__':

    k = bytes.fromhex('db166448527a4c23940f637b2248552e')
    fixed = bytes.fromhex('93ca96d0')
    gcm = Cipher_AES_128_GCM(k,fixed)


    c=b'\x00\x00\x00\x00\x00\x00\x00\x00\xcb\x8e\xd1V\xdf`\xdf\xd4HLFiS\x1c\xe9=~1KB\xc8\xb8\x8e\x84lJ\xe5w\xedi^\xd3'
    a=b'\x00\x00\x00\x00\x00\x00\x00\x00\x16\x03\x03\x00\x10'
    seq = b'\x00' * 8
    p = gcm.decrypt(c, a, seq)
