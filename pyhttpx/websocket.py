
import asyncio
import struct
import hashlib
import base64
import os

from urllib.parse import urlparse
import socket

from pyhttpx.layers.tls.pyaiossl import SSLContext,PROTOCOL_TLSv1_2
from pyhttpx.exception import (
    SwitchingProtocolError,
    SecWebSocketKeyError,
    WebSocketClosed
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
    def __init__(self, url=None, headers=None, loop=None, ja3=None, exts_payload=None,ping=False):
        self._urlparse = urlparse(url)
        self.headers = headers or DEFAULT_HEADERS
        self.ja3 = ja3
        self.exts_payload = exts_payload
        self.ping = ping
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

        self.load = True

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None

    async def close(self):
        await self.send(struct.pack('!H', 1000).decode('latin1'), binary=True, opc=0b1000)
        self.open = False

    async def connect(self):
        context = SSLContext(PROTOCOL_TLSv1_2)

        context.set_payload(browser_type='chrome', ja3=self.ja3, exts_payload=self.exts_payload)

        self.sock = context.wrap_socket()
        await self.sock.connect(self.addres)

        await self.on_open()
        self.open = True

        if self.ping:
            self.loop.create_task(self.loop_ping())

        return self

    def check_proto(self, data):

        data = data.decode()
        proto, status_code = data.split('\r\n',1)[0].split(' ')[:2]
        head = {}

        if status_code == '101':
            for i in data.split('\r\n')[1:]:
                k, v = i.split(':', 1)
                k, v = k.strip(), v.strip()
                head[k.lower()] = v

            sec_websocket_key = self.sec_websocket_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            sec_websocket_accept = head['sec-websocket-accept']

            b = base64.b64encode(hashlib.sha1(sec_websocket_key.encode('latin1')).digest())
            if b != sec_websocket_accept.encode():
                raise SecWebSocketKeyError('sec_websocket_key verify failed')
        else:
            raise SwitchingProtocolError(f"host={self.addres[0]},path={self.path},switching protocol error,status_code {status_code},text: {data}")

    async def on_open(self):

        self.sec_websocket_key = base64.b64encode(os.urandom(16)).decode()
        self.headers['Sec-WebSocket-Key'] = self.sec_websocket_key

        request_header = [f'GET {self.path} HTTP/1.1']
        for k,v in self.headers.items():
            request_header.append(f'{k}: {v}')

        request_header = '\r\n'.join(request_header)
        request_header += '\r\n\r\n'

        await self.sock.sendall(request_header.encode())
        data = await self.sock.recv(2**12)

        self.head_data, self.body_data = data.split(b'\r\n\r\n',1)
        self.check_proto(self.head_data)

        self.cache_buffer = b''
        self.reader_buffer = b''
        self.cache_buffer += self.body_data

        return True

    async def send(self, data: str, binary: bool=True, opc: int=None):

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

    async def flush(self ,data):
        self.cache_buffer += data
    async def handle(self):

        #self.cache_buffer += data
        if len(self.cache_buffer) < 2:
            return

        frame_head = self.cache_buffer[0]
        FIN = frame_head >> 7
        opcode = frame_head & 0b1111
        payload_len = self.cache_buffer[1] & 0b1111111

        if payload_len < 126:
            n = 2
            msg_len = payload_len
            msg = self.cache_buffer[n:n + msg_len]
            self.cache_buffer = self.cache_buffer[n + msg_len:]
        elif payload_len == 126:
            n = 4
            msg_len = struct.unpack('!H', self.cache_buffer[2:n])[0]
            msg = self.cache_buffer[n:n + msg_len]
            self.cache_buffer = self.cache_buffer[n + msg_len:]
        else:
            n = 10
            msg_len = struct.unpack('!Q', self.cache_buffer[2:n])[0]
            msg = self.cache_buffer[n:n + msg_len]
            self.cache_buffer = self.cache_buffer[n + msg_len:]

        while len(msg) < msg_len:
            #数据长度不足,缓存中的数据还属于当前帧,继续读取
            d = self.sock.recv(msg_len)
            msg += d

        if opcode == 0x00:
            self.reader_buffer += msg
        elif opcode == 0x01:
            self.reader_buffer += msg
        elif opcode == 0x02:
            self.reader_buffer += msg
        elif opcode == 0x08:
            self.open = False
            await self.close()
            raise WebSocketClosed(f'webscoket Closed')

        elif opcode == 0x9:
            # 收到ping,发送pong

            await self.send(msg, binary=False, opc=0xA)

        elif opcode == 0xA:
            # pong
            pass

        if FIN == 1:
            reader_buffer = self.reader_buffer
            self.reader_buffer = b''
            return reader_buffer

        else:
            pass
    async def recv(self):

        while 1:
            #握手过程产生的缓存数据
            result = await self.handle()
            if result:
                return result
            try:
                data = await self.sock.recv(2 ** 14)
            except ConnectionResetError:
                self.open = False
                raise WebSocketClosed('webscoket Closed')
            else:
                if data is None:
                    self.open = False
                    raise WebSocketClosed('webscoket Closed')
                await self.flush(data)


    async def loop_ping(self):
        while 1:
            s = os.urandom(4).decode('latin1')
            await self.send(s,binary=True, opc=0x09)
            await asyncio.sleep(20)





