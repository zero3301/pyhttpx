import struct
import six
from typing import Generic,TypeVar

T = TypeVar('T')

class GenericMeta(type):
    def __getitem__(self, item):
        return self
class Extension_metaclass(GenericMeta):
    def __new__(cls, name, base, attrs):
        new_cls = type.__new__(cls, name, base, attrs)
        return new_cls


class Extension(six.with_metaclass(Extension_metaclass)):
    #协议扩展
    def __bytes__(self):
        return b''

    @classmethod
    def dump(self, **kwargs):
        pass
class ExtServerName(Extension):
    _type = 0x00
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x00' + struct.pack('!H',len(host)) + host.encode()
        temp = struct.pack('!H',len(temp)) + temp
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

    name = 'HostName'
    fields_desc = [
        b'\x00',
    ]


class ExtExTenedMasterSecret(Extension):
    _type = 0x17

    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b''
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtRenegotitationInfo(Extension):
    #65281
    _type = 0xff01
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x00'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtSupportedGroups(Extension):
    _type = 0x0a
    @classmethod
    def dump(cls,host=None,**kwargs):
        #x25519
        #temp = b'\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01'
        #secp256r1
        #firefox
        temp = b'\x00\x17\x00\x18\x00\x19'
        temp = b'\x00\x17'
        temp = b'%s%s' % (struct.pack('!H',len(temp)), temp)
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtEcPoint(Extension):
    _type = 0x0b
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x00'
        temp = b'%s%s' % (struct.pack('!B',len(temp)), temp)
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtSessionTicket(Extension):
    _type = 0x23
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b''
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtNextProtocolNegotiation(Extension):
    _type = 0x3374
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b''

        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtApplicationLayerProtocolNegotiation(Extension):
    _type = 0x10
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x02\x68\x31\x08' + 'http/1.1'.encode()
        temp = b'%s%s' % (struct.pack('!H',len(temp)), temp)
        #firefox34
        temp=bytes.fromhex('001908737064792f332e3106737064792f3308687474702f312e31')
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtStatusRequest(Extension):
    _type = 0x05
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x01\x00\x00\x00\x00'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtDelegatedCredentials(Extension):
    _type = 0x22
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtKeyShare(Extension):
    _type = 0x33
    @classmethod
    def dump(cls, pubkey=b'',client_pubkey=b''):

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
class ExtSupportVersions(Extension):
    _type = 0x2b
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x04\x03\x04\x03\x03'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtSignatureAlgorithms(Extension):
    _type = 0x0d
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'
        #firefox34
        temp = bytes.fromhex('001004010501020104030503020304020202')
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtPskKeyExchangeModes(Extension):
    _type = 0x2d
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x01\x01'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class ExtRecordSizeLimit(Extension):
    _type = 0x1c
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b'\x40\x01'
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

class ExtPadding(Extension):
    _type = 0x15
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = bytes(134)

        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)
class Extja3(Extension):
    _type = 0x66
    @classmethod
    def dump(cls,host=None,**kwargs):
        temp = b''
        return b'%s%s%s' % (struct.pack('!H',cls._type),struct.pack('!H',len(temp)), temp)

ext_ja3 = {
        0: ExtServerName,
        65281: ExtRenegotitationInfo,
        10: ExtSupportedGroups,
        11: ExtEcPoint,
        35: ExtSessionTicket,
        13172: ExtNextProtocolNegotiation,
        16: ExtApplicationLayerProtocolNegotiation,
        5:  ExtStatusRequest,
        13: ExtSignatureAlgorithms,


    }

def dump_extension(host=None,ja3=None):
    #771,4865,0-65281-10-51-43-13-45,29-23,0

    if not ja3:
        exts = [
            ExtServerName.dump(host=host),#10
            #ExtExTenedMasterSecret.dump(),#23,扩展主密钥，加入上下文
            ExtRenegotitationInfo.dump(),#0xff01
            ExtSupportedGroups.dump(),#10
            ExtEcPoint.dump(),#11,dh椭圆曲线点
            ExtSessionTicket.dump(),#35,会话复用
            ExtNextProtocolNegotiation.dump(),#0x3374
            ExtApplicationLayerProtocolNegotiation.dump(),#16，应用层协议1.1
            ExtStatusRequest.dump(),#5
            #ExtDelegatedCredentials.dump(),#34
            #ExtKeyShare.dump(),#51，存放dh公钥，减少往返请求
            #ExtSupportVersions.dump(),#43
            ExtSignatureAlgorithms.dump(),#13
            #ExtPskKeyExchangeModes.dump(),#45，tls1.3用到,1.2不支持
            #ExtRecordSizeLimit.dump(),#28
            #ExtPadding.dump(),#21
            #Extja3().dump()

               ]
    else:
        exts = [ext_ja3[e].dump(host=host) for e in ja3 if ext_ja3.get(e)]

    temp = b''.join(exts)
    return b'%s%s' % (struct.pack('!H',len(temp)), temp)


#ja3 = [0, 65281, 10 ,11,35,13172,16,5,13]
