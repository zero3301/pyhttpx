import struct

import random
from typing import Generic,TypeVar

_tls_ext_cls = {}
class ExtensionMetaclass(type):
    def __new__(cls, name, base, attrs):
        new_cls = type.__new__(cls, name, base, attrs)
        if name.startswith("Ext"):
            _tls_ext_cls[new_cls._type] = new_cls
        return new_cls


class _BaseExtension(metaclass=ExtensionMetaclass):

    def __bytes__(self):
        return b''


    def dump(self, host, context):
        _type = self.fields_desc[0]
        payload = self.fields_desc[1]
        if isinstance(payload, str):
            payload = payload.encode('latin1')

        s = b'%s%s%s' % (struct.pack('!H', _type), struct.pack('!H', len(payload)), payload)
        return s

class ExtServerName(_BaseExtension):
    _type = 0x00
    payload = ''
    fields_desc = [
        _type,
        payload
    ]

    def dump(self, host, context):
        temp = b'\x00' + struct.pack('!H',len(host)) + host.encode()
        self.payload = struct.pack('!H',len(temp)) +  temp
        self.fields_desc[1] = self.payload

        return super().dump(host, context)


class ExtExTenedMasterSecret(_BaseExtension):
    _type = 0x17
    payload = ''
    fields_desc = [
        _type,
        payload,
    ]

class ExtRenegotitationInfo(_BaseExtension):
    _type = 0xff01
    payload = '\x00'
    fields_desc = [
        _type,
        payload,
    ]
class ExtSupportedGroups(_BaseExtension):
    _type = 0x0a
    payload = b'\x00\x1d\x00\x17\x00\x18\x00\x19'
    fields_desc = [
        _type,
        payload,
    ]
    def dump(self, host, context):
        supported_groups = context.supported_groups or self.payload
        self.payload = struct.pack('!H',len(supported_groups)) +  supported_groups
        self.fields_desc[1] = self.payload

        return super().dump(host, context)


class ExtEcPoint(_BaseExtension):
    _type = 0x0b
    payload = b'\x00'
    fields_desc = [
        _type,
        payload,
    ]
    def dump(self, host, context):
        ec_points = context.ec_points or self.payload
        self.payload = struct.pack('!B',len(ec_points)) +  ec_points
        self.fields_desc[1] = self.payload

        return super().dump(host, context)

class ExtSessionTicket(_BaseExtension):
    _type = 0x23
    payload = ''
    fields_desc = [
        _type,
        payload,
    ]

class _ExtNextProtocolNegotiation(_BaseExtension):
    _type = 0x3374
    payload = ''
    fields_desc = [
        _type,
        payload,
    ]

class ExtApplicationLayerProtocolNegotiation(_BaseExtension):
    #应用层协议扩展,暂不支持http2
    _type = 0x10
    payload = '\x00\x09\x08http/1.1'
    #h2
    #payload = bytes.fromhex('000c02683208687474702f312e31')
    fields_desc = [
        _type,
        payload,
    ]

    def dump(self, host, context):

        if context.http2:
            payload = bytes.fromhex('000c02683208687474702f312e31')
        else:
            payload = bytes.fromhex('000908687474702f312e31')
        self.fields_desc[1] = payload

        return super().dump(host, context)

class ExtApplicationSettings(_BaseExtension):

    _type = 0x4469
    payload = bytes.fromhex('0003026831')
    #payload = bytes.fromhex('0003026832')
    fields_desc = [
        _type,
        payload,
    ]
    def dump(self, host, context):
        if context.http2:
            payload = bytes.fromhex('0003026832')
        else:
            payload = bytes.fromhex('0003026831')
        self.fields_desc[1] = payload

        return super().dump(host, context)


class ExtStatusRequest(_BaseExtension):
    _type = 0x05
    payload = '\x01\x00\x00\x00\x00'
    fields_desc = [
        _type,
        payload,
    ]
class ExtDelegatedCredentials(_BaseExtension):
    _type = 0x22
    payload = '\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03'
    fields_desc = [
        _type,
        payload,
    ]

class ExtSignatureAlgorithms(_BaseExtension):
    _type = 0x0d
    payload = b'\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'
    fields_desc = [
        _type,
        payload,
    ]
    def dump(self, host, context):
        if context.browser_type == 'chrome':
            payload = bytes.fromhex('04030804040105030805050108060601')
        else:
            payload = b'\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'

        self.payload = struct.pack('!H', len(payload)) + payload
        self.fields_desc[1] = self.payload

        return super().dump(host, context)

class ExtRecordSizeLimit(_BaseExtension):
    _type = 0x1c
    payload = '\x40\x01'
    fields_desc = [
        _type,
        payload,
    ]


#tls1.3
class ExtKeyShare(_BaseExtension):
    _type = 0x33
    payload = bytes.fromhex('0029aaaa000100001d002049266d1d91aaa329581793362977e7cf0a17a70ed23bcbfb5cf64e31697af80f')
    fields_desc = [
        _type,
        payload,
    ]
    def dump(self, host, context):
        if context.browser_type == 'chrome':
            group_rand_key = b'\xfa\xfa' + struct.pack('!H', 1) + b'\x00'
            group_x25519_key = b'\x00\x1d' + struct.pack('!H', len(context.group_x25519_key)) + context.group_x25519_key
            key =  group_rand_key + group_x25519_key
        else:
            group_x25519_key = b'\x00\x1d' + struct.pack('!H',len(context.group_x25519_key)) + context.group_x25519_key
            group_secp_key = b'\x00\x17' + struct.pack('!H', len(context.group_secp_key)) + context.group_secp_key

            key = group_x25519_key + group_secp_key
        self.payload = struct.pack('!H', len(key)) + key
        self.fields_desc[1] = self.payload

        return super().dump(host, context)


class ExtPskKeyExchange_modes(_BaseExtension):
    _type = 0x2d
    payload = '\x01\x01'
    fields_desc = [
        _type,
        payload,
    ]

class ExtSupportdVersions(_BaseExtension):
    _type = 0x2b
    payload = '\x04\x03\x04\x03\x03'
    fields_desc = [
        _type,
        payload,
    ]
    def dump(self, host, context):

        if context.browser_type == 'chrome':
            self.payload = '\x06\xda\xda\x03\x04\x03\x03'
            #self.payload = '\x02\x03\x03'
        else:
            self.payload = '\x04\x03\x04\x03\x03'
        self.fields_desc[1] = self.payload

        return super().dump(host, context)


class ExtCompressCertificate(_BaseExtension):
    _type = 0x1b
    payload = '\x02\x00\x02'
    fields_desc = [
        _type,
        payload,
    ]

class ExtPadding(_BaseExtension):
    _type = 0x15
    payload = bytes(135)
    fields_desc = [
        _type,
        payload,
    ]


def make_randext(host, ext_type, payload=None,context=None):

    if payload is None:
        #强制使用内置扩展数据
        if ext_type in _tls_ext_cls.keys():
            payload = _tls_ext_cls[ext_type].payload
        else:
            payload = ''
    fields_desc = [
        ext_type,
        payload,
    ]
    ext = type('=^_^=', (_BaseExtension,), dict(fields_desc=fields_desc))
    return ext().dump(host, context)


def dump_extension(host, context):
    #771,4865,0-65281-10-51-43-13-45,29-23,0
    #exts=None, exts_payload=None

    exts = context.exts
    exts_payload = context.exts_payload
    ext_data = []

    if exts_payload is None:
        exts_payload = {}
    if not exts:
        for e in list(_tls_ext_cls.values())[:]:
            ext_data.append(e().dump(host, context))

    else:
        for e in exts:
            if _tls_ext_cls.get(e):
                d = _tls_ext_cls.get(e)().dump(host, context)
            else:
                payload = exts_payload.get(e)
                d = make_randext(host, e, payload)
            ext_data.append(d)
    temp = b''.join(ext_data)
    return b'%s%s' % (struct.pack('!H',len(temp)), temp)


if __name__ == '__main__':

    exts = [0, 65281, 10 ,11,35,13172,16,5,13,222]
    exts_payload = {222: 'a'}

    host = '127.0.0.1'


