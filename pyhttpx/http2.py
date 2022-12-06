import time
from urllib.parse import urlencode

from pyhttpx.layers.tls.pyssl import SSLContext,PROTOCOL_TLSv1_2
import socket
import struct

from hpack import (
    Encoder,
    Decoder,
    HeaderTuple,
    InvalidTableIndex,

)



import json
import inspect
import platform
import sys
import time

from queue import LifoQueue
import queue
from threading import RLock
import threading


from urllib.parse import urlencode

from pyhttpx.layers.tls import pyssl
from pyhttpx.compat import *
from pyhttpx.models import Request
from pyhttpx.utils import default_headers,log,Conf


from pyhttpx.models import Response,Http2Response
from pyhttpx.exception import TooManyRedirects


a = 1
if a==1:
    def make_stream(typeid: int, flag: int, streamid: int, data: bytes):
        "构造数据帧"
        length = struct.pack('!I', len(data))
        typeid = struct.pack('!B', typeid)
        flag = struct.pack('!B', flag)
        streamid = struct.pack('!I', streamid)
        frame = b'%s%s%s%s' % (length, typeid, flag, streamid)
        return frame


    magic = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    setting = make_stream(
        typeid=4, flag=0, streamid=0, data=bytes.fromhex('000100010000000400020000000500004000')
    )
    update_window = make_stream(
        typeid=8, flag=0, streamid=0, data=bytes.fromhex('00bf0001')

    )
    prioritys = [
        make_stream(
            typeid=2, flag=0, streamid=3, data=bytes.fromhex('0000000000c8')
        ),
        make_stream(
            typeid=2, flag=0, streamid=5, data=bytes.fromhex('000000000064')
        ),
        make_stream(
            typeid=2, flag=0, streamid=7, data=bytes.fromhex('000000000000')
        ),
        make_stream(
            typeid=2, flag=0, streamid=9, data=bytes.fromhex('000000000700')
        ),
        make_stream(
            typeid=2, flag=0, streamid=11, data=bytes.fromhex('000000000300')
        ),
        make_stream(
            typeid=2, flag=0, streamid=13, data=bytes.fromhex('0000000000f0')
        ),
    ]
    s1 = magic + setting + update_window + b''.join(prioritys)

    s1 = bytes.fromhex(
        '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001204000000000000010001000000040002000000050000400000000408000000000000bf000100000502000000000300000000c800000502000000000500000000640000050200000000070000000000000005020000000009000000070000000502000000000b000000030000000502000000000d00000000f0')


class CookieJar(object):
    __slots__ = ('name', 'value', 'expires', 'max_age', 'path', 'domain')
    def __init__(self, name=None, value=None, expires=None, max_age=None, path=None, domain=None):
        self.name = name
        self.value = value


class CookieManger(object):
    def __init__(self):
        self.cookies = {}
    def set_cookie(self,req: Request, cookie: dict) ->None:
        addr = (req.host, req.port)

        if self.cookies.get(addr):
            self.cookies[addr].update(cookie)
        else:
            self.cookies[addr] = cookie
    def get(self, k):
        return self.cookies.get(k ,{})

class HTTPSConnectionPool:
    scheme = "https"
    maxsize = 100
    def __init__(self,**kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']
        self.req = kwargs.get('request')

        self.ja3 = kwargs.get('ja3')
        self.exts_payload = kwargs.get('exts_payload')
        self.poolconnections = LifoQueue(maxsize=self.maxsize)
        self.lock = RLock()

    def _new_conn(self):

        context = pyssl.SSLContext(http2=True)
        context.set_payload(browser_type='chrome',ja3=self.ja3,exts_payload=self.exts_payload)

        conn = context.wrap_socket(
            sock=None,server_hostname=None)

        conn.connect((self.req.host,self.req.port), timeout=self.req.timeout, proxies=self.req.proxies, proxy_auth=self.req.proxy_auth)
        return conn

    def _get_conn(self):
        conn = None
        try:
            conn = self.poolconnections.get(block=False)

        except queue.Empty:
            pass
        return conn or self._new_conn()

    def _put_conn(self, conn):
        try:
            self.poolconnections.put(conn, block=False)
            return
        except queue.Full:
            # This should never happen if self.block == True
            log.warning(
                "Connection pool is full, discarding connection: %s. Connection pool size: %s",
                '%s' % self.host,
                self.maxsize,
            )


class Http2Session(object):

    def __init__(self, ja3=None, exts_payload=None, http2=True):
        self.tls_session = None
        self.cookie_manger = CookieManger()
        self.http2 = http2
        self.active_addr = None
        self.tlss = {}
        self.cookie_dict = {}
        self.ja3 = None
        self.exts_payload = exts_payload

    def handle_cookie(self, req, set_cookies):
        #
        if not set_cookies:
            return
        c = {}
        if isinstance(set_cookies, str):
            for set_cookie in set_cookies.split(';'):
                if set_cookie:
                    k, v = set_cookie.split('=', 1)
                    k,v = k.strip(),v.strip()
                    c[k] = v
        elif isinstance(set_cookies, list):
            for set_cookie in set_cookies:
                k, v = set_cookie.split(';')[0].split('=', 1)
                k, v = k.strip(), v.strip()
                c[k] = v
        elif isinstance(set_cookies, dict):
            c.update(set_cookies)

        self.cookie_manger.set_cookie(req,c)


    def request(self, method, url,update_cookies=True,timeout=None,proxies=None,proxy_auth=None,
                params=None, data=None, headers=None, cookies=None,json=None,allow_redirects=True,verify=None):

        #多线程,采用局部变量
        req = Request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            data=data or {},
            json=json,
            cookies=cookies or {},
            params=params or {},
            timeout=timeout,
            proxies=proxies,
            proxy_auth=proxy_auth,
            allow_redirects=allow_redirects,

        )

        addr = (req.host, req.port)
        if req.headers.get('Cookie'):
            self.handle_cookie(req ,req.headers.get('Cookie'))

        if cookies:
            self.handle_cookie(req, cookies)

        _cookies = self.cookie_manger.get(addr)
        send_kw  = {}
        if _cookies:
            send_kw['Cookie'] = '; '.join('{}={}'.format(k,v) for k,v in _cookies.items())

        msg = self.prep_request(req, send_kw)
        resp = self.send(req, msg, update_cookies)
        return resp



    def prep_request(self, req, send_kw) -> bytes:
        #msg = b'%s %s HTTP/1.1\r\n' % (req.method.encode(), req.path.encode())
        msg = b''
        return msg

    def get_conn(self,req, addr):
        self.active_addr = addr
        if self.tlss.get(addr):
            connpool = self.tlss[addr]
            conn = connpool._get_conn()

        else:

            connpool = HTTPSConnectionPool(request=req,
                                           host=req.host,
                                           port=req.host,
                                           ja3=self.ja3,
                                           exts_payload=self.exts_payload
                                           )
            self.tlss[addr] = connpool
            conn = connpool._get_conn()

        return connpool, conn

    def send(self, req, msg, update_cookies):
        self.first_load = True
        self.stream_id = 15
        self.settings_msg = bytes.fromhex(
            '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001204000000000000010001000000040002000000050000400000000408000000000000bf000100000502000000000300000000c800000502000000000500000000640000050200000000070000000000000005020000000009000000070000000502000000000b000000030000000502000000000d00000000f0')

        addr = (req.host, req.port)
        connpool, conn = self.get_conn(req, addr)

        self.handle_cookie(req ,req.cookies)
        _cookies = self.cookie_manger.get(addr)

        if req.data:
            if isinstance(req.data, str):
                d = req.data.encode()

            elif isinstance(req.data, dict):
                d = urlencode(req.data).encode()
        elif req.json:
            d = json.dumps(req.json).encode()
        else:
            d = b''

        data = struct.pack('!I', len(d))[1:] + b'\x00\x01' + struct.pack('!I', self.stream_id) + d
        self.stream_id = 15
        ua = req.headers['user-agent']
        s = [
            (':method', req.method),
            (':path', req.path),
            (':authority', req.host),
            (':scheme', 'https'),
            ('user-agent', ua),
            ('accept', '*/*'),
            ('accept-language', 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'),
            ('accept-encoding', 'gzip, deflate, br'),
            ("content-type","application/x-www-form-urlencoded")


        ]

        if req.method == 'POST':
            s.append(('content-length', len(d)),)

        if _cookies:
            for k,v in _cookies.items():
                s.append(
                    ('cookie', f'{k}={v}')
                )
        self.hpack_encode = Encoder()
        self.hpack_decode = Decoder()

        msg2 = self.hpack_encode.encode(s)

        b = b'\x00\x00\x00\x0d\x29'
        flag =  b'\x01\x24' if req.method == 'POST' else b'\x01\x25'

        msg2 = struct.pack('!I', len(msg2) + 5, )[1:] + flag + struct.pack('!I',
                                                                                  self.stream_id) + b + msg2

        if self.first_load or 1==1:
            conn.sendall(self.settings_msg)

        update  = b'\x00\x00\x04\x08\x00' + struct.pack('!I',self.stream_id ) + b'\x00\xbe\x00\x00'
        msg2 = msg2
        conn.sendall(msg2)

        if req.method == 'POST':
            conn.sendall(data)



        response = Http2Response()
        cache = b''

        self.first_load = False
        while 1:

            r = conn.recv()
            print('r=',r)
            if not r:
                conn.isclosed = True
                break

            cache += r
            while cache:
                if len(cache) >= 9:
                    frame_len = 9 + struct.unpack('!I', b'\x00' + cache[:3])[0]
                    if len(cache) >= frame_len:
                        frame = cache[:frame_len]
                        cache = cache[frame_len:]
                        response.flush(frame)
                        if frame[3] == 7:
                            # GOWAY

                            #conn.sendall(bytes.fromhex('0000080700000000000000000000000000'))
                            #break
                            pass
                        elif frame[3] == 4:
                            #setting
                            if frame[4] == 1:
                                #conn.sendall(bytes.fromhex('000000040100000000'))
                                pass

                        elif frame[3] == 6:
                            pass
                            # GOWAY
                            #0000080600000000000000000000000000
                            #conn.sendall(bytes.fromhex('0000080600000000000000000000000000'))
                        elif frame[3] == 8:
                            pass

                    else:
                        break

                else:
                    break

            if response.read_ended:
                break



        self.stream_id += 2
        set_cookie = response.headers.get('set-cookie')
        if set_cookie :
            self.handle_cookie(req, set_cookie)

        response.request = req
        response.request.raw = msg
        set_cookie = response.headers.get('set-cookie')
        if set_cookie and update_cookies:
            self.handle_cookie(req, set_cookie)

        response.cookies = response.headers.get('set-cookie', {})
        self._content = response.content
        if not conn.isclosed:
            #h2 霍夫曼存在bug, 不使用连接池
            #connpool._put_conn(conn)
            pass

        return response

    @property
    def cookies(self):
        _cookies = self.cookie_manger.get(self.active_addr)
        return _cookies

    def get(self, url, **kwargs):
        resp = self.request('GET', url, **kwargs)
        return resp

    def post(self,url, **kwargs):
        return self.request('POST', url, **kwargs)

    @property
    def content(self):
        return self._content

    def close(self):
        self.tlss.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()








