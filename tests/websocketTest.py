"""
docs
pyhttpx.websocket

"""

import asyncio
from pyhttpx import WebSocketClient

class WSS:
    def __init__(self,url=None, headers=None, loop=None):
        self.url = url
        self.headers = headers
        self.loop = loop
        #self.ja3 = '771,19018-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,27242-29-23-24,0'

    async def connect(self):
        self.sock = await WebSocketClient(url=self.url, headers=self.headers, loop=self.loop,
                                          ).connect()


    async def send(self):
        while 1:
            if self.sock.open:
                data = '3301'
                print('send',data)
                await self.sock.send(data, binary=True)
                await asyncio.sleep(3)

    async def recv(self):
        while 1:
            r = await self.sock.recv()
            print('recv',r)


def main():
    loop = asyncio.get_event_loop()
    url = 'wss://www.python-spider.com/api/challenge62'
    print(f'connect: {url}')
    headers = {
        'Connection': 'Upgrade' ,
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
        'Upgrade': 'websocket',
        'Sec-WebSocket-Version': '13' ,
        'Accept-Encoding': 'gzip, deflate, br' ,
        'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8' ,
        'Sec-WebSocket-Key': 'p1+bsFFmXixD+hk1CHG+3w==',
        'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits' ,

    }

    wss = WSS(url, headers, loop)
    loop.run_until_complete(wss.connect())
    loop.create_task(wss.send())
    loop.create_task(wss.recv())
    loop.run_forever()

if __name__ == '__main__':
    main()