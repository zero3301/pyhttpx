from pyhttpx.layers.tls.pyaiossl import SSLContext,PROTOCOL_TLSv1_2
import asyncio
import struct
import socket
import time

class WSSClient:
    def __init__(self, url):
        self.addres = url.split('//')[1].split(':')
        self.host = self.addres[0]
        self.port = int(self.addres[1])
        #self.host = 'premws-pt3.365lpodds.com'
        #self.port = 443

    async def __aenter__(self):

        addres = (self.host, self.port)
        print(addres)
        context = SSLContext(PROTOCOL_TLSv1_2)
        self.sock = context.wrap_socket()
        #await self.sock.connect(addres)
        print('finish')
        await self.on_open()
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):

        return None




    async def on_open(self):

        path = '/chat'
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock.connect(('127.0.0.1', 6324))
        s1 = b'GET /chat HTTP/1.1\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: zh,zh-CN;q=0.9,en;q=0.8\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\nHost: 127.0.0.1\r\n\r\nPragma: no-cache\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nSec-WebSocket-Key: cOWgTjByglEg/h0pH8Ujtw==\r\nSec-WebSocket-Protocol: zap-protocol-v2\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36\r\n\r\n'

        #await self.sock.sendall(s1)
        #data = await self.sock.recv(8888)
        self.sock.sendall(s1)
        data = self.sock.recv(8888)
        print(data)




    async def send(self, data):
        import os
        FIN  = 0b10000000
        RSV1 = 0b0000000
        RSV2 = 0b000000
        RSV3 = 0b00000
        opencode = 0b0001

        head_frame = FIN | RSV1 | RSV2 | RSV3 | opencode
        data = 'a' * (2 ** 17)
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

        print(bin(s[0]))
        print(bin(s[1]))

        mask_key = os.urandom(4)
        s += mask_key
        for i in range(len(data)):
            n = ord(data[i]) ^ (mask_key[i % 4])
            s += struct.pack('!B', n)


        self.sock.sendall(s)


    async def recv(self):
        r = self.sock.recv(6324)
        return r

async def main():

    url = 'wss://127.0.0.1:6324'
    async with WSSClient(url) as wss:

        d = 'hello'
        await wss.send(d)
        while 1:
            r = await wss.recv()
            print(r)
            await asyncio.sleep(1)

if __name__ == '__main__':

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

    loop.run_forever()

    data = 'hello'
    mask_key = bytes.fromhex('3e21ac5c')

    s = b''
    for i in range(len(data)):
        a = ord(data[i]) ^ mask_key[i % 4]
        s += struct.pack('!B', a)

    print(s.hex())

