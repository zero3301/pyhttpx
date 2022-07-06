from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization,hashes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec


class X25519:
    def __init__(self, ):

        self.client_kx_privkey = x25519.X25519PrivateKey.generate()
    def create_x25519(self):
        self.client_kx_privkey = x25519.X25519PrivateKey.generate()
        #私钥对象转bytes
        # r1 = self.client_kx_privkey.private_bytes(
        #                 serialization.Encoding.Raw,
        #                 serialization.PrivateFormat.Raw,
        #                 serialization.NoEncryption(),
        #             )
        # 私钥bytes转object
        # client_kx_privkey = x25519.X25519PrivateKey.from_private_bytes(r1)
        return self.client_kx_privkey
    def test(self):
        x1 = self.create_x25519()
        x2 = self.create_x25519()
        """
        公钥bytes转object
        # publickey1 = x1.public_key().public_bytes(
        #                 serialization.Encoding.Raw,
        #                 serialization.PublicFormat.Raw
        #             )

        #公钥bytes转object
        #x25519.X25519PublicKey.from_public_bytes(publickey2)
        #pms = x1.exchange(x25519.X25519PublicKey.from_public_bytes(publickey2))
        #pms2 =x2.exchange(x25519.X25519PublicKey.from_public_bytes(publickey1))
        """
        pms = x1.exchange(x2.public_key())
        pms2 = x2.exchange(x1.public_key())
        print('pms',pms)
        print( pms == pms2)


class ECDHE:
    #curvename='secp256r1'协商共享密钥
    def __init__(self,curvename):
        self.curvename = curvename

        private = 84415227458779726660992473430064037894301106473964382056643694469597835968918
        self.private = bytes.fromhex(hex(private)[2:])
        self.curve = ec.SECP256R1()

        self.client_kx_privkey = ec.generate_private_key(self.curve,backend=default_backend())

        #print(self.client_kx_privkey.private_numbers().private_value)
        p1 = b'\x04\xde\x8a #\xc0J/\xa8\xa1\xc7\x82,O4\xcb\x08\xcc\x10\x96\x81\xd8#\x8e\x7fd~1\x80\x82HHm\xdcK\xee\x90>\x8f\xb5\xaa\x05\xc3\x92H\xe1jD,W\x8d_^\x03\xa8D\x046#\x97}4\x1c\xc6\x03'
        publickey = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve,
            p1
        )
        pms = self.client_kx_privkey.exchange(ec.ECDH(),publickey)
        #b"\xc0\x95\xab\x84\x9f\x8a\xbf[O\xe2\xbdG\xb9\xc8d!\xe8'Z/F\x03\xef%\xa6b\xa9_|\x91/)"



    def create(self):

        self.client_kx_privkey = ec.generate_private_key(self.curve, self.private)
        return self.client_kx_privkey

    def test(self):
        """
        公钥对象转bytes
        pubkey = client_kx_privkey.public_key()
        publickey_bytes = pubkey.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
        )
        #公钥bytes转对象
        publickey = ec.EllipticCurvePublicKey.from_encoded_point(
                    self.curve,
                    publickey_bytes
                )
        :return:
        """
        c1 = self.create()
        c2 = self.create()
        pms = c1.exchange(ec.ECDH(), c2.public_key())
        pms2 = c2.exchange(ec.ECDH(), c1.public_key())

        publickey_bytes = c1.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
        )



if __name__ == '__main__':
    
    curvename = 'secp256r1'
    ECDHE(curvename)
    
    
    import tinyec.registry as ec_reg
    import tinyec.ec as tinec
    curve = ec_reg.get_curve('secp256r1')
    private = 84415227458779726660992473430064037894301106473964382056643694469597835968918
    client_keypair = tinec.Keypair(curve, private)
    server_keypair = tinec.Keypair(curve, private)
    # client_keypair = tinec.make_keypair(curve)
    # server_keypair = tinec.make_keypair(curve)
    point = client_keypair.pub
    x, y = hex(point.x)[2:].rjust(64, '0'), hex(point.y)[2:].rjust(64, '0')
    pubkey = "%s%s" % (x, y)
    publickey_bytes = b'\x04' + bytes.fromhex(pubkey)
    secret_point1 = tinec.ECDH(client_keypair).get_secret(server_keypair)
    
    
    _point = (
    int(publickey_bytes[1:33].hex(), 16),
    int(publickey_bytes[33:].hex(), 16),
    )
    
    point = tinec.Point(curve, *_point)
    client_keypair = tinec.Keypair(curve, None, point)
    secret_point2 = tinec.ECDH(server_keypair).get_secret(client_keypair)
