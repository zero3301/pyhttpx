import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import time

from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )

class CHACHA20POLY1305:

    def encrypt(self, key, iv, aad, plaintext):
        chacha = ChaCha20Poly1305(key)
        ct = chacha.encrypt(iv, plaintext, aad)
        return ct

    def decrypt(self, key, iv, aad, ciphertext):
        chacha = ChaCha20Poly1305(key)
        ct = chacha.decrypt(iv, ciphertext, aad)
        return ct

if __name__ == '__main__':
    import base64
    import struct
    def hextob(a):
        return bytes.fromhex(a.replace(' ', ''))


    cha = CHACHA20POLY1305()

    A = hextob("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7")
    K = hextob('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f')
    P = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    N = hextob('07 00 00 00 40 41 42 43 44 45 46 47')

    C= cha.encrypt(K, N, A, P)
    P = cha.decrypt(K,N,A, C)

    print(P)


