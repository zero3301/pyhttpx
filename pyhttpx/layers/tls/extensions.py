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
    _type = 0x10
    payload = '\x00\x09\x08http/1.1'
    fields_desc = [
        _type,
        payload,
    ]
class ExtStatusRequest(_BaseExtension):
    _type = 0x05
    payload = '\x01\x00\x00\x00\x00'
    fields_desc = [
        _type,
        payload,
    ]
class __ExtDelegatedCredentials(_BaseExtension):
    _type = 0x22
    payload = '\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03'
    fields_desc = [
        _type,
        payload,
    ]
class __ExtSupportVersions(_BaseExtension):
    _type = 0x2b
    payload = '\x02\x03\x03'
    fields_desc = [
        _type,
        payload,
    ]
class ExtSignatureAlgorithms(_BaseExtension):
    _type = 0x0d
    payload = '\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'
    fields_desc = [
        _type,
        payload,
    ]
class ExtRecordSizeLimit(_BaseExtension):
    _type = 0x1c
    payload = '\x40\x00'
    fields_desc = [
        _type,
        payload,
    ]
class __ExtPadding(_BaseExtension):
    _type = 0x15
    payload = bytes(random.randint(0,100))
    fields_desc = [
        _type,
        payload,
    ]


def make_randext(host, ext_type, payload=None,context=None):
    if payload is None:
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


