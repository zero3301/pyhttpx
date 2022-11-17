import os
import struct


verify_data = []
class _TLSHandshake:
    pass
class TLSClientHello(_TLSHandshake):
    name = "TLS Handshake - Client Hello"


class HandshakeClientHello:
    "hello 握手包"
    def __init__(self,ciphersuites,extensions):
        self.contentType = b'\x01'
        self.length = None
        self.version = b'\x03\x03'
        self.random = os.urandom(32)
        self.sessionId = b'\x20' + os.urandom(32)
        self.cipherSuites = ciphersuites
        self.compreession = b'\x01\x00'
        self.extension = extensions

    def dump(self):
        body = self.version + self.random + self.sessionId + self.cipherSuites + self.compreession + \
            self.extension

        return self.contentType + struct.pack('!I', len(body))[1:] + body


class HelloClient:
    """hello 包"""
    def __init__(self,ciphersuites, extensions):
        self.contentType = b'\x16'
        self.version = b'\x03\x01'
        self.length = None
        self.hanshake = HandshakeClientHello(ciphersuites, extensions)
        self.hd = self.hanshake.dump()

    def dump(self,sc):
        sc.handshake_data.append(self.hd)
        return self.contentType + self.version + struct.pack('!H',len(self.hd)) + self.hd
