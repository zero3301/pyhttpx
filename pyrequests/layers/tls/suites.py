
import struct

CIPHER_SUITES = [ 0xc02b,0xc02f]

#firefox34

# CIPHER_SUITES = [
#     0xc02b,0xc02f,0xc00a,0xc009,
#     0xc013,0xc014,0xc007,0xc011,
#     0x0033,0x0032,0x0039,0x002f,
#     0x0035,0x000a,0x0005,0x0004
# ]


class CipherSuites:
    #密码套件RSA_WITH_AES_128_GCM_SHA256

    def __init__(self):
        self.datas = CIPHER_SUITES

    def dump(self):
        temp = b''.join([struct.pack('!H',i) for i in self.datas])

        return  struct.pack('!H', len(temp)) + temp
