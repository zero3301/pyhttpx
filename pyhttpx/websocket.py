from pyhttpx.layers.tls.pyaiossl import SSLContext,PROTOCOL_TLSv1_2
import asyncio
import struct
import socket
import time
import hashlib
import base64
import os

from urllib.parse import urlparse


from pyhttpx.exception import (
    SwitchingProtocolError,
    SecWebSocketKeyError,
    WebSocketClosedError
)

DEFAULT_HEADERS = {
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
        }
class WebSocketClient:
    def __init__(self, url=None, headers=None, loop=None):
        self._urlparse = urlparse(url)
        self.headers = headers or DEFAULT_HEADERS

        if ':' in self._urlparse.netloc:
            host = self._urlparse.netloc.split(':')[0]
            port = self._urlparse.netloc.split(':')[1]
            self.addres = (host, int(port))
        else:
            self.addres = (self._urlparse.netloc, 443)

        self.headers['Host'] = self.addres[0]

        if not self._urlparse.path:
            self.path = '/'
        elif self._urlparse.query:
            self.path = f'{self._urlparse.path}?{self._urlparse.query}'
        else:
            self.path = self._urlparse.path

        self.open = None
        self.loop = loop or asyncio.get_event_loop()
        self.buffer = b''


    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

    async def close(self):
        await self.send('\x00', binary=True, opc=0b1000)
        self.open = False

    async def connect(self):
        context = SSLContext(PROTOCOL_TLSv1_2)

        self.sock = context.wrap_socket()
        await self.sock.connect(self.addres)
        await self.on_open()
        self.open = True
        self.loop.create_task(self.ping())
        return self

    def check_proto(self, data: str):
        data = data.strip()
        proto, status_code, _, _ = data.split('\r\n',1)[0].split(' ')
        head = {}
        for i in data.split('\r\n')[1:]:
            k,v = i.split(':', 1)
            k,v = k.strip(), v.strip()
            head[k] = v
        if status_code == '101':
            # verify
            # sec = b64(sha258EAFA5-E914-47DA-95CA-C5AB0DC85B11)
            sec_websocket_key = self.sec_websocket_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            sec_websocket_accept = head['Sec-Websocket-Accept']

            b = base64.b64encode(hashlib.sha1(sec_websocket_key.encode('latin1')).digest())
            if b != sec_websocket_accept.encode():
                raise SecWebSocketKeyError('sec_websocket_key verify failed')
        else:
            raise SwitchingProtocolError(f'switching protocol error, status_code {status_code}')
    async def on_open(self):

        #self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        #self.sock.connect(self.addres)
        self.sec_websocket_key = base64.b64encode(os.urandom(20)).decode()
        #self.sec_websocket_key = '5d2W0zCfJZ2Mapyun85U3w=='
        self.headers['Sec-Websocket-Key'] = self.sec_websocket_key

        request_header = ['GET /chat HTTP/1.1']
        for k,v in self.headers.items():
            request_header.append(f'{k}: {v}')

        request_header = '\r\n'.join(request_header)
        request_header += '\r\n\r\n'

        await self.sock.sendall(request_header.encode())
        data = await self.sock.recv(4096)
        self.check_proto(data.decode())
        self.reader_buffer = b''
        return True

    async def send(self, data, binary=True,opc=None):

        FIN  = 0b10000000
        RSV1 = 0b0000000
        RSV2 = 0b000000
        RSV3 = 0b00000
        opcode = 0b0010 if binary else 0b0001
        if opc:
            #
            opcode = opc
        head_frame = FIN | RSV1 | RSV2 | RSV3 | opcode

        s = struct.pack('!B', head_frame)
        if len(data) < 126:
            MASK = 0b10000000
            MASK |= len(data)
            m = struct.pack('!B', MASK)
            s += m
        elif 126 <= len(data) <= 2 ** 16 -1:
            MASK = 0b10000000
            MASK |= 126
            m = struct.pack('!B', MASK)
            s += m
            s += struct.pack('!H', len(data))
        elif 2 ** 16 -1 <  len(data) <= 2**64 -1:
            MASK = 0b10000000
            MASK |= 127
            m = struct.pack('!B', MASK)
            s += m
            s += struct.pack('!Q', len(data))

        else:
            raise OverflowError('data length more than 64 byte')

        mask_key = os.urandom(4)
        s += mask_key
        for i in range(len(data)):
            n = ord(data[i]) ^ (mask_key[i % 4])
            s += struct.pack('!B', n)
        await self.sock.sendall(s)

    async def recv(self, size=1024):
        while 1:
            data = await self.sock.recv(2 ** 14)
            data += self.buffer
            self.buffer = b''
            frame_head = data[0]
            FIN = frame_head >> 7
            opcode = frame_head & 0b1111
            payload_len = data[1] & 0b1111111

            if payload_len < 126:
                n = 2
                msg_len = payload_len
                msg = data[n:n+msg_len]
                self.buffer = data[n+msg_len:]
            elif payload_len == 126:
                n = 4
                msg_len = struct.unpack('!H', data[2:n])[0]
                msg = data[n:n+msg_len]
                self.buffer = data[n + msg_len:]
            else:
                n=10
                msg_len = struct.unpack('!Q', data[2:n])[0]
                msg = data[n:n + msg_len]
                self.buffer = data[n + msg_len:]

            if len(msg) < msg_len:
                print(payload_len)

            while len(msg) < msg_len:
                d = self.sock.recv(msg_len)
                msg += d

            if opcode == 0x00:
                self.reader_buffer += msg
            if opcode == 0x01:
                self.reader_buffer += msg
            elif opcode == 0x02:
                self.reader_buffer += msg
            elif opcode == 0x08:
                self.open = False
                raise  WebSocketClosedError(' closed')
            elif opcode == 0xA:
                #pong
                pass

            if FIN == 1:
                reader_buffer = self.reader_buffer
                self.reader_buffer = b''
                return reader_buffer if opcode == 0x02 else reader_buffer.decode()

            else:
                pass

    async def ping(self):
        while 1:
            await self.send('\x00',binary=True, opc=0x09)
            await asyncio.sleep(30)





