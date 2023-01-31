
import json
import inspect
import platform
import sys
import time
import copy
from queue import LifoQueue
import queue
from threading import RLock
import threading
import struct

from urllib.parse import urlencode

from pyhttpx.layers.tls import pyssl
from pyhttpx.compat import *
from pyhttpx.models import Request
from pyhttpx.utils import default_headers,log,Conf
from pyhttpx.models import Response,Http2Response
from pyhttpx.exception import TooManyRedirects


from hpack import (
    Encoder,
    Decoder,
)
class CookieJar(object):
    __slots__ = ('name', 'value', 'expires', 'max_age', 'path', 'domain')
    def __init__(self, name=None, value=None, expires=None, max_age=None, path=None, domain=None):
        self.name = name
        self.value = value

def find_second_last(text, pattern):
    return text.rfind(pattern, 0, text.rfind(pattern))

def get_top_domain(url):
    i = find_second_last(url,'.')
    domain = url if i == -1 else url[i:]
    return domain

class CookieManger(object):
    def __init__(self):
        self.cookies = {}
    def set_cookie(self,req: Request, cookie: dict) ->None:
        addr = get_top_domain(req.host)

        if self.cookies.get(addr):
            self.cookies[addr].update(cookie)
        else:
            self.cookies[addr] = cookie
    def get(self, k):
        return self.cookies.get(k ,{})

class HTTPSConnectionPool:
    scheme = "https"
    maxsize = 50
    def __init__(self,**kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']
        self.req = kwargs.get('request')

        self.ja3 = kwargs.get('ja3')
        self.browser_type = kwargs.get('browser_type')
        self.exts_payload = kwargs.get('exts_payload')
        self.http2 = kwargs.get('http2')
        self.poolconnections = LifoQueue(maxsize=self.maxsize)
        self.lock = RLock()

    def _new_conn(self):

        context = pyssl.SSLContext(http2=self.http2)
        context.set_payload(self.browser_type,self.ja3,self.exts_payload)
        conn = context.wrap_socket(
            sock=None,server_hostname=None)

        conn.connect(
            (self.req.host,self.req.port),
            timeout=self.req.timeout,
            proxies=self.req.proxies,
            proxy_auth=self.req.proxy_auth)

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


class HttpSession(object):
    def __init__(self, ja3=None, exts_payload=None, browser_type=None, http2=True):
        #默认开启http2, 最终协议由服务器协商完成
        self.http2 = http2
        self.tls_session = None
        self.cookie_manger = CookieManger()
        self.browser_type = None
        self.active_addr = None
        self.tlss = {}
        self.browser_type = browser_type or 'chrome'
        self.exts_payload = exts_payload
        self.lock = RLock()
        self.ja3 = ja3

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
        self.req = req
        if req.headers.get('Cookie'):
            self.handle_cookie(req ,req.headers.get('Cookie'))

        if cookies:
            self.handle_cookie(req, cookies)

        _cookies = self.cookie_manger.get(get_top_domain(self.req.host))
        send_kw  = {}
        if _cookies:
            send_kw['Cookie'] = '; '.join('{}={}'.format(k,v) for k,v in _cookies.items())


        #if conn.context.application_layer_protocol_negotitaion
        addr = (req.host, req.port)
        self.connpool, self.conn = self.get_conn(req, addr)

        if self.conn.context.application_layer_protocol_negotitaion == 'h2':
            resp = self.http2_send(req,)

        else:
            msg = self.prep_request(req, send_kw)
            resp = self.send(req, msg, update_cookies)

        return resp

    def handle_redirect(self, resp):

        if resp.status_code == 302 and resp.request.allow_redirects:
            location = resp.headers['location']
            from urllib.parse import urlsplit
            parse_location  =urlsplit(location)

            if not parse_location.netloc:
                location = f'https://{resp.request.host}{location}'


            for i in range(Conf.max_allow_redirects):
                resp = self.request('GET', location)

                if resp.status_code != 302:
                    break
            else:
                raise TooManyRedirects('too many redirects')

        return resp

    def prep_request(self, req, send_kw) -> bytes:

        msg = b'%s %s HTTP/1.1\r\n' % (req.method.encode('latin1'), req.path.encode('latin1'))
        dh = copy.deepcopy(req.headers) or default_headers()
        dh.update(send_kw)

        dh['Host'] = req.host
        req_body = ''

        if req.method == 'POST':
            if req.data:
                if isinstance(req.data, str):
                    req_body = req.data

                elif isinstance(req.data, dict):
                    req_body = urlencode(req.data)

            elif req.json:
                req_body = json.dumps(req.json, separators=(',', ':'))

            dh['Content-Length'] = len(req_body)

        for k, v in dh.items():
            msg += ('%s: %s\r\n' % (k, v)).encode('latin1')

        msg += b'\r\n'
        msg += req_body.encode('latin1')
        return msg

    def get_conn(self,req, addr):
        self.active_addr = addr

        ## not support
        if self.tlss.get(addr):
            connpool = self.tlss[addr]
            conn = connpool._get_conn()
        else:
            connpool = HTTPSConnectionPool(request=req,
                                           host=req.host,
                                           port=req.host,
                                           ja3=self.ja3,
                                           exts_payload=self.exts_payload,
                                           browser_type = self.browser_type,
                                           http2 = self.http2,

                                           )


            # 代理连接池没有实现,如果使用代理,会导致使用同一个代理ip连接
            # http2 存在bug
            # closed
            # self.tlss[addr] = connpool
            conn = connpool._get_conn()

        return connpool, conn

    def send(self, req, msg, update_cookies):
        #http/1.1
        #msg = bytes.fromhex('474554202f434349452f5363686564756c655f4c61622f434349454f6e6c696e652f434349454f6e6c696e6520485454502f312e310d0a486f73743a20636369652e636c6f7564617070732e636973636f2e636f6d0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b207836343b2072763a3130362e3029204765636b6f2f32303130303130312046697265666f782f3130362e300d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f617669662c696d6167652f776562702c2a2f2a3b713d302e380d0a4163636570742d4c616e67756167653a207a682d434e2c7a683b713d302e382c7a682d54573b713d302e372c7a682d484b3b713d302e352c656e2d55533b713d302e332c656e3b713d302e320d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174652c2062720d0a444e543a20310d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a5365632d46657463682d446573743a20646f63756d656e740d0a5365632d46657463682d4d6f64653a206e617669676174650d0a5365632d46657463682d536974653a206e6f6e650d0a5365632d46657463682d557365723a203f310d0a507261676d613a206e6f2d63616368650d0a43616368652d436f6e74726f6c3a206e6f2d63616368650d0a0d0a')
        self.conn.sendall(msg)
        response = Response()
        while 1:
            r = self.conn.recv()
            if not r:
                self.conn.isclosed = True
                break
            else:
                response.flush(r)

            connection = response.headers.get('connection','')
            if response.read_ended:
                if connection != 'keep-alive':
                    self.conn.isclosed = True
                break

            #头部没有长度字段
            if 'timeout' in connection:
                pass

        response.request = req
        response.request.raw = msg
        set_cookie = response.headers.get('set-cookie')
        if set_cookie and update_cookies:
            self.handle_cookie(req, set_cookie)
        c = {}
        if set_cookie:
            for cook in set_cookie:
                k, v = cook.split(';', 1)[0].split('=', 1)
                c[k] = v
        response.cookies = c
        self._content = response.content
        if not self.conn.isclosed:
            self.connpool._put_conn(self.conn)

        return response

    def http2_send(self, req):

        self.first_load = True
        self.stream_id = 1
        self.settings = bytes.fromhex('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001e0400000000000001000100000002000000000003000003e800040060000000060004000000000408000000000000ef0001')

        if req.data:
            if isinstance(req.data, str):
                req_body = req.data.encode('latin1')

            elif isinstance(req.data, dict):
                req_body = urlencode(req.data).encode('latin1')

            else:
                raise TypeError('data type error')
        elif req.json:
            req_body = json.dumps(req.json).encode('latin1')
        else:
            req_body = b''

        dh = {
            ':method': req.method,
            ':authority': req.host,
            ':scheme': 'https',
            ':path': req.path,
        }
        headers = copy.deepcopy(req.headers) or default_headers()

        for k,v in headers.items():
            k = k.lower()
            dh[k] = v
        if req.method == 'POST':
            dh['content-length'] = len(req_body)

        head_block = []
        for k,v in dh.items():
            if not k in ['connection','host']:
                head_block.append((k,v))

        _cookies = self.cookie_manger.get(get_top_domain(self.req.host))

        if _cookies:
            for k,v in _cookies.items():
                head_block.append(
                    ('cookie', f'{k}={v}')
                )

        self.hpack_encode = Encoder()
        self.hpack_decode = Decoder()
        request_msg = self.hpack_encode.encode(head_block)

        stream_dependency_weight = b'\x80\x00\x00\x00'
        weight = b'\xff'
        stream_type = b'\x01'
        stream_flag =  b'\x24' if req.method == 'POST' else b'\x25'

        stream_header = b''.join([
            struct.pack('!I', len(request_msg) + 5, )[1:],
            stream_type,
            stream_flag,
            struct.pack('!I', self.stream_id),
            stream_dependency_weight,
            weight,
            request_msg
        ])
        #update = b'\x00\x00\x04\x08\x00' + struct.pack('!I', self.stream_id) + b'\x00\xbe\x00\x00'

        if self.first_load or 1==1:
            self.conn.sendall(self.settings)
            #self.conn.sendall(update)

        self.conn.sendall(stream_header)
        if req.method == 'POST':
            size = 2 ** 12
            while req_body:
                block = req_body[:size]
                req_body = req_body[size:]
                #\x00继续帧,\x01结束帧
                stream_type = b'\x00'
                stream_flag = b'\x00' if len(req_body) > 0 else b'\x01'
                stream_data = b''.join([
                    struct.pack('!I', len(block))[1:],
                    stream_type,
                    stream_flag,
                    struct.pack('!I', self.stream_id),
                    block
                ])
                self.conn.sendall(stream_data)

        response = Http2Response()
        cache = b''
        self.first_load = False
        while 1:
            r = self.conn.recv()
            if not r:
                self.conn.isclosed = True
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
                            # goway
                            # conn.sendall(bytes.fromhex('0000080700000000000000000000000000'))
                            pass

                        elif frame[3] == 4:
                            # setting
                            if frame[4] == 1:
                                self.conn.sendall(bytes.fromhex('000000040100000000'))
                                pass

                        elif frame[3] == 6:
                            pass

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
        response.request.raw = head_block
        set_cookie = response.headers.get('set-cookie')
        if set_cookie :
            self.handle_cookie(req, set_cookie)

        c = {}
        if set_cookie:
            for cook in set_cookie:
                k, v = cook.split(';', 1)[0].split('=', 1)
                c[k] = v
        response.cookies = c
        self._content = response.content
        return response

    @property
    def cookies(self):
        _cookies = self.cookie_manger.get(get_top_domain(self.req.host))
        return _cookies

    @cookies.setter
    def cookies(self, value):
        self.cookie_manger.cookies[get_top_domain(self.req.host)] = value
    def get(self, url, **kwargs):
        resp = self.request('GET', url, **kwargs)
        resp = self.handle_redirect(resp)
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









