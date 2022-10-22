
import struct
from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends.openssl.backend import backend


class AES_GCM(object):
    def encrypt(self, key, nonce, data,aad):
        cipher = AESGCM(key)
        t = cipher.encrypt(nonce, data, aad)
        return t

    def decrypt(self, key, nonce, data,aad):
        t = AESGCM(key).decrypt(nonce, data, aad)
        return t



class AES_CBC:
    block_size = 16
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


    def encrypt(self, key,nonce,data):
        cipher = Cipher(algorithms.AES(key), modes.CBC(nonce),backend=backend)
        encryptor = cipher.encryptor()
        data = self._tls_padding(data)
        #data = self._padding(data)
        ct1 = encryptor.update(data)
        ct2 = encryptor.finalize()
        return ct1 + ct2

    def decrypt(self, key,nonce,data):
        cipher = Cipher(algorithms.AES(key), modes.CBC(nonce),backend=backend)
        decryptor = cipher.decryptor()

        ct = decryptor.update(data) + decryptor.finalize()
        ct = self._tls_upadding(ct)
        return ct

if __name__ == '__main__':
    import os

    aes = AES_GCM()
    k = b'1' * 16
    n = os.urandom(12)
    a = b'1' * 16

    p = b'abc'
    c=aes.encrypt(k, n,p,a)
    aes.decrypt(k,n,c,a)

















