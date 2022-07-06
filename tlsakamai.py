#tls1.2 demo
#mofei
#2022-4-14

import struct
import os
import time
import socket


import OpenSSL
import rsa


from pyrequests.crypto.prf import *
from pyrequests.config import *
from pyrequests.crypto.aes import AES_GCM


verify_data = []
class Extension:
    #协议扩展
    pass

class ExtServerName:
    _type = 0x00
    @classmethod
    def dump(cls,host):
        temp = b'\x00' + struct.pack('!H',len(host)) + host.encode()
        temp = struct.pack('!H',len(temp)) + temp
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtExTenedMasterSecret:
    _type = 0x17
    #_type = 0xaa
    @classmethod
    def dump(cls):
        temp = b''
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtRenegotitationInfo:
    _type = 0xff01
    @classmethod
    def dump(cls):
        temp = b'\x00'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtSupportedGroups:
    _type = 0x0a
    @classmethod
    def dump(cls):
        temp = b'\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01'
        if secp == 1:
            temp = b'\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01'
        temp = b'%s%s' % (struct.pack('!H',len(temp)), temp)
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtEcPoint:
    _type = 0x0b
    @classmethod
    def dump(cls):
        temp = b'\x00'
        temp = b'%s%s' % (struct.pack('!B',len(temp)), temp)
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtSessionTicket:
    _type = 0x23
    @classmethod
    def dump(cls):
        temp = b''
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtNextProtocolNegotiation:
    _type = 0x3374
    @classmethod
    def dump(cls):
        temp = b''

        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtApplicationLayerProtocolNegotiation:
    _type = 0x10
    @classmethod
    def dump(cls):
        temp = b'\x02\x68\x31\x08' + 'http/1.1'.encode()
        temp = b'%s%s' % (struct.pack('!H',len(temp)), temp)
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtStatusRequest:
    _type = 0x05
    @classmethod
    def dump(cls):
        temp = b'\x01\x00\x00\x00\x00'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtDelegatedCredentials:
    _type = 0x22
    @classmethod
    def dump(cls):
        temp = b'\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtKeyShare:
    _type = 0x33
    @classmethod
    def dump(cls, pubkey=b'',client_pubkey2=b''):

        #temp = bytes.fromhex(s)
        #x25519
        temp = b'\x00\x1d' + struct.pack('!H',len(bytes(32))) + bytes(32)
        #secp256r1
        #temp = b'\x00\x17' + struct.pack('!H', len(pubkey)) + pubkey

        r2 = b'\x04' + bytes(64)
        r2  =b'\x00\x17\x00\x41' + r2
        temp = temp + r2
        temp = b'%s%s' % (struct.pack('!H',len(temp)), temp)
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtSupportVersions:
    _type = 0x2b
    @classmethod
    def dump(cls):
        temp = b'\x04\x03\x04\x03\x03'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtSignatureAlgorithms:
    _type = 0x0d
    @classmethod
    def dump(cls):
        temp = b'\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtPskKeyExchangeModes:
    _type = 0x2d
    @classmethod
    def dump(cls):
        temp = b'\x01\x01'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtRecordSizeLimit:
    _type = 0x1c
    @classmethod
    def dump(cls):
        temp = b'\x40\x01'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtPadding:
    _type = 0x15
    @classmethod
    def dump(cls):
        temp = bytes(134)

        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
def dump_extension(host, pubkey=None,client_pubkey2=None):
    #771,4865,0-65281-10-51-43-13-45,29-23,0
    arr = [
        ExtServerName.dump(host),#10
        #ExtExTenedMasterSecret.dump(),#23,扩展主密钥，加入上下文
        ExtRenegotitationInfo.dump(),#65281
        ExtSupportedGroups.dump(),#10
        ExtEcPoint.dump(),#11,dh椭圆曲线点
        ExtSessionTicket.dump(),#35,会话复用
        ExtNextProtocolNegotiation.dump(),
        ExtApplicationLayerProtocolNegotiation.dump(),#16，应用层协议1.1
        ExtStatusRequest.dump(),#5
        #ExtDelegatedCredentials.dump(),#34
        #ExtKeyShare.dump(),#51，存放dh公钥，减少往返请求
        #ExtSupportVersions.dump(),#43
        ExtSignatureAlgorithms.dump(),#13
        #ExtPskKeyExchangeModes.dump(),#45，tls1.3用到,1.2不支持
        #ExtRecordSizeLimit.dump(),#28
        #ExtPadding.dump(),#21

           ]
    temp = b''.join(arr)
    return b'%s%s' % (struct.pack('!H',len(temp)), temp)

class cipherSuites:
    #密码套件RSA_WITH_AES_128_GCM_SHA256
    suites = {
        0x009c: 'RSA_WITH_AES_128_GCM_SHA256',
        0xc02f: 'ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        0x1301: 'TLS_AES_128_GCM_SHA256',
        0x1302: 'TLS_AES_256_GCM_SHA384'
    }
    def __init__(self):

        self.datas = CIPHER_SUITES
    def dump(self):
        temp = b''.join([struct.pack('!H',i) for i in self.datas])

        return  struct.pack('!H', len(temp)) + temp

class HandshakeClientHello:
    "hello 握手包"
    def __init__(self,host):
        self.contentType = b'\x01'
        self.length = None
        self.version = b'\x03\x03'
        self.random = os.urandom(32)
        self.sessionId = b'\x00'
        self.cipherSuites = cipherSuites().dump()
        self.compreession = b'\x01\x00'
        self.extension = dump_extension(host)

    def dump(self):
        body = self.version + self.random + self.sessionId + self.cipherSuites + self.compreession + \
            self.extension

        return self.contentType + struct.pack('!I', len(body))[1:] + body


class HelloClient:
    """hello 包"""
    def __init__(self,host):
        self.contentType = b'\x16'
        self.version = b'\x03\x03'
        self.length = None
        self.hanshake = HandshakeClientHello(host)
        self.hanshake_data = self.hanshake.dump()

    def dump(self):
        verify_data.append(self.hanshake_data)
        return self.contentType + self.version + struct.pack('!H',len(self.hanshake_data)) + self.hanshake_data

class ServerStore:
    def load(self,flowtext):
        self.random = flowtext[6:6+32]
        sessionlength = struct.unpack('!B', flowtext[38:39])[0]
        self.sessionId = flowtext[39:39+32]
        return self

def encrypt(plaintxt, publickey):
    #rsa
    return rsa.encrypt(plaintxt, publickey)

class CertificateContext:
    def load(self,flowtext):
        first_cer_length = b'\x00' + flowtext[7:10]
        first_cer_length = struct.unpack('!I',first_cer_length)[0]
        cert = flowtext[10:10 + first_cer_length]

        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        pulicKey = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.cert.get_pubkey())
        print('取消证书验证')
        #self.rsapulicKey = rsa.PublicKey.load_pkcs1_openssl_pem(pulicKey)
        return self

class ServerContext:
    random = None
    sessionId = None
    done = False
    @classmethod
    def load(self,flowtext):
        handshake_type = struct.unpack('!B',flowtext[:1])[0]
        if handshake_type == 0x02:
            #server hello
            self.serverstore = ServerStore().load(flowtext)
        elif handshake_type == 0x0b:
            self.certificatecontext= CertificateContext().load(flowtext)
        elif handshake_type == 0x0c:

            self.serverpubkey = flowtext[8:8+32]
            if secp == 1:
                self.serverpubkey = flowtext[8:8 + 65]
            print('*** 注意ECDHE公钥是否正确 = ', self.serverpubkey.hex())

        elif handshake_type == 0x0e:
            self.done = True

        return self
class ClientKeyExchange:
    def __init__(self, premaster):
        self.content_type = b'\x16'
        self.version = b'\x03\x03'
        self.premaster = premaster

    def handshake(self):
        premaster = struct.pack('!B',len(self.premaster)) + self.premaster
        handshake_type = b'\x10'
        length = struct.pack('!I',len(premaster))[1:]

        return b'%s%s%s' % (handshake_type, length, premaster)

    def dump(self):
        handshake = self.handshake()
        verify_data.append(handshake)
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
    def load(self, premaster, client, server):
        self.premaster = premaster
        self.client = client
        self.server = server
        self.init()

        return self
    def init(self):

        self.master_secret()
        self.key_expandsion()
        #256
        self.client_write_key = self.keyBlock[:16]
        self.server_write_key = self.keyBlock[16:32]
        self.client_fixed_iv = self.keyBlock[32:36]
        self.server_fixed_iv = self.keyBlock[36:40]
        #384
        # self.client_write_key = self.keyBlock[:32]
        # self.server_write_key = self.keyBlock[32:64]
        # self.client_fixed_iv = self.keyBlock[64:68]
        # self.server_fixed_iv = self.keyBlock[68:72]

    def master_secret(self):
        label = b'master secret'
        #label = b'extended master secret'
        seed = label + self.client.random + self.server.random

        #seed = label + hashlib.sha256(b''.join(verify_data)).digest()
        self.masterSecret = prf(self.premaster, seed, outlen=48)

    def key_expandsion(self):
        seed = b'key expansion' + self.server.random + self.client.random
        self.keyBlock = prf(self.masterSecret, seed, outlen=128)
class Socket():
    def __init__(self):
        self.socket = None

    def connect(self, address : tuple):
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.connect(address)


    def listen(self):

        from pyrequests.crypto.ecc import ECDHE,X25519
        c1 = X25519()
        hello = HelloClient(host)
        self.socket.send(hello.dump())
        servercontext = ServerContext()
        self.client_seq = 0
        self.server_seq = 0
        self.done = False

        exchanage  = True

        from copy import deepcopy
        cache =b''
        plaintexts = b''
        while 1:
            recv = self.socket.recv(8126)


            print('recv', recv)
            recv = cache + recv
            cache = b''
            print('cache',recv)
            if recv:
                while recv:
                    #if len(recv) <= 5:
                        #break
                    handshake_type = struct.unpack('!B', recv[:1])[0]
                    length = struct.unpack('!H', recv[3:5])[0]
                    flowtext = recv[5:5 + length]

                    if len(flowtext) != length:
                        cache = deepcopy(recv[:])
                        break

                    if handshake_type == 0x16:
                        verify_data.append(flowtext)
                        servercontext.load(flowtext)
                    elif handshake_type == 0x14:

                        print('finsh')
                        self.server_seq +=1
                        data = b'{"startDate": "2022-07-02", "endDate": "2022-07-03", "hotelMnemonics": ["SZXSF"], "rates": {"ratePlanCodes": [{"internal": "IVANI"}]}, "products": [{"productTypeCode": "SR", "adults": 1, "children": 0, "quantity": 1}], "options": {"offerIds": null, "loyalty": {"loyaltyId": null}, "disabilityMode": "ACCESSIBLE_AND_NON_ACCESSIBLE"}}'
                        cookie = b'_abck=3A90C26E1EEAC7DA8378FB5562856EF5~0~YAAQlW2bG4uy/6+BAQAAVWbXsghn+d+Rv0q3n6zkNKmneJQiGpN+rCEFjcz4bcSSNqIbklhltYUTQ91APSJOSCYcTkWHJkdFiiQl1MbOD6j1Tlnm6Zw/wlZJyOy6YMdtuc6sanU18wU/4o+UWkiY5EAzffgD1wQ7W1F87ryP9H8C+p2rM5AIk6ysSneW0dkYPsUcBLlkGXSJyULfKW4TkzFAAv55G56Uk8Tht1nrUJXsV4ki/AvqLEf7n7TrA+AgLFKsrkinvWm5szg7dNRRPfv6NopRTSoKNvDERuIVH88Vo20uhbnj4I9oMbS61s2xJsTKfGCORAkDfpna8uNemcgEeFwB9p86DodSUzpeHtzPJyQQBxmpELfJBKOxyWRsI0O55oMpyuZq+fA2IJGOJ6UZ534DVbJiFg==~-1~-1~-1; ak_bmsc=BE0FF3AA5212EE3A81A45F6715F76A91~000000000000000000000000000000~YAAQlW2bG/Kx/6+BAQAA2hXXshAJQftvtnBrXTgO9O5fZDAzdQlnjVC4KlsdcIJomlhDAeIPuNfFGjYZZVXBz1etBe1Wqw2NAu1BPH/2RtJ0e8G8qXHVR1A3tSXda5CmV7wi1dxOTTc9q4HOv+fZ/S6QGxSGkBQaTDCs2K1A0E2KAygvTtwlfF2mbe+H4f7DNYfLafuhTWB7/90ZqaKy9vubZ0xT480KJ9U46heUJgUJrhWn/kpanj+7ZtTowYrzgW0w7NxezCdZDv8lv52/8a4H+jK4NJiExwzGCAkEoklcYLrjjeLoj01R+ZnR5mMjeQfDwT5/imSl2B9pV3Y2QJO3aPA88w0xrgDzwWQwDyRIKhzbSp7ZVJDG2JKkNyw9DHu6UsvM3lwhbffdb2i/tTbhjFeKYLkchZD2jyoqSPnT4cEYD98RVrF3QbTaPlh/GXXkaz4J8fjPCmNKAI0hwBo4haNp; bm_sz=C0E022A35BFB45938B64F9CDB3EEA0DB~YAAQlW2bG7mx/6+BAQAAf+nWshAD6kiknAuJ3YSpK0c6UAdoqHcX0nwiRAhPdOqeA9fffjUP2AaDQf8z/nD84I2ZCxWIk3MUKqBURw1MZnRZzvgvsel0UWkqFekOqZsoWlF7EJ9pwUcpqUSbryqn0fhz60+CC2zvFUCB4obSJLS7se/QAyno87qca5qaJanAjqc2izt6yzF7cXiR0yHJbzFfIONBKEYg9fgj7YQUtBH5yVm/idkiRnLgvHd0FbDKw91jiIR9JOJz4/7bkHFape7ecAS85/ZAYRi1C9ESEiPEsnc=~4338224~3424823; roomKeyCookie=1656562840; CopterConnect=B229BB78-65EB-4128-9562-6BEC44A1811F%7Cae020d407073c7e711f5649ef9844ec4%7CIHGRoomkeypop; bm_sv=5D9181155E8D2EF63A149CAE0C1E7C1A~YAAQlW2bGyqz/6+BAQAA5s3XshBKpTXIMx/JU9C70JhehaAYmhORTJkBVxNe16bcbqnbT72yrvLK5+4pPAfdbIQqPsDkg1YvBkpEItvKNJWh2tzicQKYYPz3dae/Wog8t6FjueJp9ZgRBj2UfaqFjyIx+X6BdkcURgQKXJRf3A3wPnHdDLsV95GX9V6lXG9MReT4n8sCjcOXsp2CA1BI5E3BTNzuZxA6PugJ/0q4WMn58qzwtPF/zKO/zKZ94vke~1; AMCV_8EAD67C25245B1870A490D4C%40AdobeOrg=1585540135%7CMCIDTS%7C19174%7CMCMID%7C75664073510848634290726469033036263427%7CMCAID%7CNONE%7CMCOPTOUT-1656570050s%7CNONE%7CMCAAMLH-1657167650%7C11%7CMCAAMB-1657167650%7Cj8Odv6LonN4r3an7LhD3WZrU1bUpAkFkkiY1ncBR96t2PTI%7CvVersion%7C4.4.0; check=true; ensUID=18121220sX4ZvhXG9Wf9; mbox=session#603d3d63c912497982e8e82999805c93#1656564714|PC#603d3d63c912497982e8e82999805c93.32_0#1719807652; AMCVS_8EAD67C25245B1870A490D4C%40AdobeOrg=1; mboxEdgeCluster=32; gig_bootstrap_4_jpzahMO4CBnl9Elopzfr0A=identity_ver4; notice_behavior=implied,eu; notice_preferences=3:; notice_gdpr_prefs=0,1,2,3:; cmapi_gtm_bl=; cmapi_cookie_privacy=permit 1,2,3,4; _uetsid=21faff20f82c11eca780ff8916df9724; _uetvid=21faf840f82c11ecaa76dffde8f0c40d'
                        #cookie = b'_abck=3A90'
                        plaintext = b'POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0\r\n' \
                                    b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' \
                                    b'Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n' \
                                    b'Accept-Encoding: gzip, deflate\r\n' \
                                    b'Content-Length: 332\r\nContent-Type: application/json\r\n' \
                                    b'Connection: keep-alive\r\n' \
                                    b'Cookie: %s\r\n' \
                                    b'X-IHG-API-KEY: 123pQM1YazQwnWi5AWXmoRoA5FSfW0S9x8A\r\n' \
                                    b'IHG-SessionId: 32ee0c2e-bfc2-4a5b-8399-fbb9c61c52dc' \
                                    b'\r\n\r\n%s\x17' % (path.encode(),host.encode(),cookie,data)

                        plaintext = b'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0\r\n' \
                                    b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' \
                                    b'Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n' \
                                    b'Accept-Encoding: gzip, deflate' \
                                    b'\r\n\r\n\x17' % (path.encode(), host.encode())

                        print('client get ')
                        print(plaintext)
                        explicit_nonce = struct.pack('!Q', self.client_seq)
                        nonce = self.keystore.client_fixed_iv + explicit_nonce

                        # 附加数据
                        aead = explicit_nonce + b'\x17\x03\x03' + struct.pack('!H', len(plaintext))
                        aes = AES_GCM()
                        # print('aead', aead)
                        # print('iv', nonce)
                        # print('plaintext', plaintext, len(plaintext))

                        ciphertext,tag = aes.aes_encrypt(self.keystore.client_write_key, nonce, aead, plaintext)
                        ciphertext = explicit_nonce + ciphertext + tag
                        encrypted_message = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
                        self.socket.send(encrypted_message)
                        self.client_seq += 1

                        #self.socket.shutdown(1)

                    elif handshake_type == 0x17:

                        print('appcation ciphertext')

                        ciphertext = flowtext
                        explicit_nonce = struct.pack('!Q', self.server_seq)
                        nonce = self.keystore.server_fixed_iv + ciphertext[:8]

                        # 附加数据
                        aead = explicit_nonce + b'\x17\x03\x03' + struct.pack('!H', len(ciphertext) - 24)
                        aes = AES_GCM()
                        # print('nonce = ',nonce)
                        # print('aead', aead)
                        explicit_nonce,ciphertext,tag = ciphertext[:8],ciphertext[8:-16],ciphertext[-16:]
                        plaintext = aes.aes_decrypt(self.keystore.server_write_key, nonce, aead, ciphertext,tag)
                        print('http plaintext')
                        print(plaintext)
                        plaintexts += plaintext
                        self.server_seq += 1
                        #http需要不同传输类型判断是否接受完毕,再结束,暂时没处理
                        Transfer_Encoding = False

                        if Transfer_Encoding:
                            pass
                        else:

                            pass


                    recv = recv[5+length:]
                if servercontext.done and exchanage:
                    print('key exchanage')
                    if secp == 1:
                        # curve = ec_reg.get_curve('secp256r1')
                        # _point = (
                        #     int(servercontext.serverpubkey[1:33].hex(), 16),
                        #     int(servercontext.serverpubkey[33:].hex(), 16),
                        # )
                        #
                        # point = ec.Point(curve, *_point)
                        # server_keypair = ec.Keypair(curve, None, point)
                        #
                        # client_keypair = ec.make_keypair(curve)
                        # secret_point = ec.ECDH(client_keypair).get_secret(server_keypair)
                        #
                        # point = hex(secret_point.x)[2:]
                        # if len(point) %2 ==1:
                        #     point = '0' + point
                        # pms = bytes.fromhex(point)
                        # point = client_keypair.pub
                        # x, y = hex(point.x)[2:].rjust(64, '0'), hex(point.y)[2:].rjust(64, '0')
                        # pubkey = "%s%s" % (x, y)
                        # publickey_bytes = b'\x04' + bytes.fromhex(pubkey)

                        from cryptography.hazmat.primitives.asymmetric import ec as ec2
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives import serialization, hashes

                        client_kx_privkey = ec2.generate_private_key(ec2.SECP256R1(), backend=default_backend())

                        server_publickey = ec2.EllipticCurvePublicKey.from_encoded_point(
                            ec2.SECP256R1(),
                            servercontext.serverpubkey
                        )
                        pms = client_kx_privkey.exchange(ec2.ECDH(), server_publickey)

                        print(len(pms),pms)
                        publickey_bytes = client_kx_privkey.public_key().public_bytes(
                            serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint
                        )

                        print(len(publickey_bytes),publickey_bytes)
                    else:
                        from cryptography.hazmat.primitives.asymmetric import x25519
                        from cryptography.hazmat.primitives import serialization, hashes

                        t1 = time.time()
                        publickey_bytes = c1.client_kx_privkey.public_key().public_bytes(
                             serialization.Encoding.Raw,
                             serialization.PublicFormat.Raw
                         )
                        pms = c1.client_kx_privkey.exchange(x25519.X25519PublicKey.from_public_bytes(servercontext.serverpubkey))
                        print(time.time() - t1)

                    print('pms = ',len(pms), pms)

                    keychange = ClientKeyExchange(publickey_bytes).dump()
                    changecipherspec =  ClientCpiherSpec().dump()
                    #self.socket.send(keychange + changecipherspec)
                    self.keystore = KeyStore().load(pms, hello.hanshake, servercontext.serverstore)

                    explicit_nonce = struct.pack('!Q',self.client_seq)

                    nonce = self.keystore.client_fixed_iv +  explicit_nonce
                    handshake = hashlib.sha256(b''.join(verify_data)).digest()
                    label = b"client finished"

                    plaintext = prf(self.keystore.masterSecret, label + handshake, outlen=12)

                    plaintext = b'\x14\x00\x00\x0c' + plaintext
                    # 附加数据
                    aead = explicit_nonce + b'\x16\x03\x03' + struct.pack('!H', len(plaintext))
                    aes = AES_GCM()

                    ciphertext, tag = aes.aes_encrypt(self.keystore.client_write_key, nonce, aead, plaintext)
                    ciphertext = explicit_nonce + ciphertext + tag

                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext )) + ciphertext
                    self.socket.send(keychange + changecipherspec +  encrypted_message)
                    self.client_seq += 1

                    exchanage = False

            else:
                break




        print(plaintexts)
        headers,body = plaintexts.split(b'\r\n\r\n',1)
        print(headers.decode())
        print(body)
        import gzip
        #print(gzip.decompress(body).decode())


if __name__ == '__main__':
    #mac正确，明文错误
    import traceback
    path = '/availability/v2/hotels/offers?fieldset=rateDetails,rateDetails.policies,rateDetails.bonusRates'
    path = '/'
    host = 'www.baidu.com'
    #host = 'www.httpbin.org'
    #host = '127.0.0.1'
    # host = 'www.ti.com'
    #host = 'www.ihg.com.cn'
    #host = 'apis.ihg.com.cn'
    port=443
    adress = (host, port)
    sess = Socket()
    t1 = time.time()
    sess.connect(adress)
    try:
        sess.listen()
    except Extension as e:
        print(traceback.format_exc())


    print(time.time() -t1)