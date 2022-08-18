

import struct
import os
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes,  # noqa: E501
                                                        BlockCipherAlgorithm,
                                                        CipherAlgorithm)
from cryptography.hazmat.backends.openssl.backend import (backend,
                                                          GetCipherByName)


_tls_block_cipher_algs = {}

class _BlockCipherMetaclass(type):
    """
    Cipher classes are automatically registered through this metaclass.
    Furthermore, their name attribute is extracted from their class name.
    """
    def __new__(cls, ciph_name, bases, dct):
        if ciph_name != "_BlockCipher":
            dct["name"] = ciph_name[7:]     # remove leading "Cipher_"
        the_class = super(_BlockCipherMetaclass, cls).__new__(cls, ciph_name,
                                                              bases, dct)
        if ciph_name != "_BlockCipher":
            _tls_block_cipher_algs[ciph_name[7:]] = the_class

        return the_class


class _BlockCipher(metaclass=_BlockCipherMetaclass):
    type = "block"

    def _tls_padding(self, data):
        '''
            需要对明文数据进行填充,其中data = 明文数据 + mac
            rfc5246
            6.2.3.2.  CBC Block Cipher
            struct {
              opaque IV[SecurityParameters.record_iv_length];
              block-ciphered struct {
                  opaque content[TLSCompressed.length];
                  opaque MAC[SecurityParameters.mac_length];
                  uint8 padding[GenericBlockCipher.padding_length];
                  uint8 padding_length;
              };
          } GenericBlockCipher;
        '''
        padding_size = self.block_size  - (len(data) % self.block_size) - 1
        pad_chr = struct.pack('!B', padding_size)
        pad = padding_size * pad_chr
        return data + pad + pad_chr

    def _tls_upadding(self, data):

        padding_size = data[-1] + 1
        return data[:-padding_size]

    def __init__(self, key=None, iv=None):

        # we use super() in order to avoid any deadlock with __setattr__
        super(_BlockCipher, self).__setattr__("key", key)
        super(_BlockCipher, self).__setattr__("iv", iv)

        if iv is None:
            iv = b'\x00' * self.block_size

        self._cipher = Cipher(self.pc_cls(key),
                              self.pc_cls_mode(iv),
                              backend=backend)


    def __setattr__(self, name, val):
        if name == "key":
            self._cipher.algorithm.key = val

        elif name == "iv":
            self._cipher.mode._initialization_vector = val

        super(_BlockCipher, self).__setattr__(name, val)

    def encrypt(self, data, A=None,nonce_explicit=None):
        #data 明文数据 + hmac
        self.iv = data[:16]
        PC = self._tls_padding(data[16:])
        encryptor = self._cipher.encryptor()
        C = encryptor.update(PC) + encryptor.finalize()
        return b'%s%s' % (self.iv,C)

    def decrypt(self, C, A=None, nonce_explicit=None):
        #C = 密文+hmac
        self.iv = C[:16]
        decryptor = self._cipher.decryptor()
        P = decryptor.update(C[16:]) + decryptor.finalize()
        P = self._tls_upadding(P)

        return P[:-self.mac_key_len]


class Cipher_AES_128_CBC(_BlockCipher):
    pc_cls = algorithms.AES
    pc_cls_mode = modes.CBC
    block_size = 16
    key_len = 16
    mac_key_len = 20
    fixed_iv_len = 0
    nonce_explicit_len = 16
    tag_len = 20

class Cipher_AES_256_CBC(Cipher_AES_128_CBC):
    key_len = 32



if __name__ == '__main__':

    import os
    key = b'1' * 16
    aes = _tls_block_cipher_algs.get('AES_128_CBC')(key=key,iv=None)

    n = b'1' * 16
    h = b'1' * 20
    p = b'a' * 16 + h

    p = n + p
    c = aes.encrypt(p)
    print(c,len(c))
    p = aes.decrypt(c)

    print(p)

