from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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

        assert pms == pms2


class ECDHE:
    #curvename='secp256r1'协商共享密钥
    def __init__(self,curvename):
        self.curvename = curvename
        #self.curve = ec.SECP256R1()
        self.curve = {
            0x0017: ec.SECP256R1(),
            0x0018: ec.SECP384R1(),
            0x0019: ec.SECP521R1(),
        }.get(self.curvename)

        self.client_kx_privkey = ec.generate_private_key(self.curve,backend=default_backend())



    def create(self):
        #临时私钥
        private = 84415227458779726660992473430064037894301106473964382056643694469597835968918
        client_kx_privkey = ec.generate_private_key(self.curve, private)
        #生成固定私钥
        client_kx_privkey = ec.derive_private_key(private,self.curve,default_backend())
        #client_kx_privkey = ec.generate_private_key(self.curve, backend=default_backend())

        return client_kx_privkey

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
        print('使用cryptography secp256r1')
        peer_private_key = self.create()
        server_private_key = self.create()

        pms1 = peer_private_key.exchange(ec.ECDH(), server_private_key.public_key())
        pms2 = server_private_key.exchange(ec.ECDH(), peer_private_key.public_key())

        print(len(pms1),pms1)
        print(pms2)
        publickey_bytes = peer_private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
        )
        sever_publickey_bytes = server_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )

        server_publickey = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve,
            sever_publickey_bytes
        )
        pms3 = peer_private_key.exchange(ec.ECDH(), server_publickey)
        print('预主密钥', len(pms1), pms1)
        print('临时公钥', publickey_bytes)
        print(pms3)

class CryptoContextFactory:
    crypto_container = {
            0x001d: X25519(),
            0x0017: ECDHE(0x0017),
            0x0018: ECDHE(0x0018),
            0x0019: ECDHE(0x0019),
    }

if __name__ == '__main__':
    
    curvename = 0x0017
    ECDHE(curvename).test()


