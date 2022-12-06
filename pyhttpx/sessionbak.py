
import json
import inspect
import platform
import sys
import time

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
from pyhttpx.utils import vprint

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

        print('self.http2=',self.http2)
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
    def __init__(self, ja3=None, exts_payload=None, browser_type=None, http2=False):
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
        msg = self.prep_request(req, send_kw)
        resp = self.send2(req, msg, update_cookies)

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
        msg = b'%s %s HTTP/1.1\r\n' % (req.method.encode(), req.path.encode())
        dh = req.headers or default_headers()
        #dh.update(req.headers)
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
        if self.tlss.get(addr) and 1 == 2:
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
            #代理连接池没有实现,如果使用代理,会导致使用同一个代理ip连接
            #self.tlss[addr] = connpool
            conn = connpool._get_conn()

        return connpool, conn
    def send(self, req, msg, update_cookies):

        addr = (req.host, req.port)
        connpool, conn = self.get_conn(req, addr)
        conn.sendall(msg)
        response = Response()
        while 1:
            r = conn.recv()

            if not r:
                conn.isclosed = True
                break
            else:
                response.flush(r)

            connection = response.headers.get('connection','')
            if response.read_ended:
                if connection != 'keep-alive':
                    conn.isclosed = True
                break

            #头部没有长度字段
            if 'timeout' in connection:
                pass

        response.request = req
        response.request.raw = msg
        set_cookie = response.headers.get('set-cookie')
        if set_cookie and update_cookies:
            self.handle_cookie(req, set_cookie)

        response.cookies = self.cookies
        self._content = response.content
        if not conn.isclosed:
            connpool._put_conn(conn)

        return response

    def send2(self, req, msg, update_cookies):
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
            # ('referer', 'https://www.ti.com/product/TLV755P?login-check=true'),
            # ('x-sec-clge-req-type', 'ajax'),
            #('content-type', 'application/json'),
            ("content-type","application/x-www-form-urlencoded")
            #('content-type', 'text/plain;charset=UTF-8'),
            #('dnt', '1'),

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
        msg2 = msg2 + update
        conn.sendall(msg2)

        if req.method == 'POST':
            conn.sendall(data)


        #conn.sendall(bytes.fromhex('000c8001240000000f0000000b1583059360e4220b677310a863b89849981c9224e41d894188f1e3c2e932e43d3f877abbd07f66a281b0dae053fae46aa43f8429a77a8102e0fb5391aa71afb53cb8d7da9677b8fbcb83fb531149d4ec0801000200a984d61653f961f797075383f963e751b0f73ad7b4fd7b9fefb4005defaf73adbf97df6800bbbf5ee75b1e6fbed00176fe8b52dc377df6800bb3f45abefb4005c5508d9bd9abfa5242cb40d25fa523b373a69d29ad171863c78f0ba4cb90f4b15d8792d2258df9f8badb7affca0f31aa5893949d604d9697408ef2b20a458944c55ac2f6593eab2f881f41f9fa507d07e75f92497ca58ae819aafb24e3b1054c1c37e159ef40853d8698d57f8e9d29ad171863c78f0ba4cb90f4ff5c8107408392a4ff810f60b249a298a78087b6a4d9ea0bda7fe10c9f5062e10e9c5fb8f570ff843d493545a93043bbfe24911ab8021657085c5c206d77db1f2f8a49a2b0d24011b25788f77ed249a2b470683fb35140d514adae05440feb91aa90fe10a881a77aa20040b8156635440e46a9c6956635440f2e34ab31aa2059dd5646fbcb83fb5440c452753aa2944008001005510309ac2ca7f2a8a57de5c11f308549a28e983f7f00ffc202887193ac0dde65c6da642cb50bd086fbee89f65d64179d71b03f7d96bffab07ffbce1876378bfdc789c1e88726abf0ec861efb65c13cdd1b611feda4b3ac6ee977bb98bccbb309fa043adde75df242976eb21d937677f3534eecc59fd7ac3b589755d9b170b47e3cb78ba7a45ee9cf9e9bd355cf44e7fc9f89a626ff3d415c8db5a58d0e1766733b9df935b9d79358b16946de2f78d85d4f67e6569b9345dc3ec3cd84e6cf6e36e88f9f72f06b95a33ffb25d4570f2cbcfb72bc49b9a2f66353a19e4ec726bdacfacc53ee0694f0dffa4cdb113ecbaf3384beaf21af047bc33809b336d72f033b2579d9ff5c62ef3c9e49d5dbededafc6663d5f6f66da1dcf776fedde1c78eed78aefe711dd930e3efb3271d5df9efedb38ebde3e3ef7f6461c81c03bf8a621e6c5fad3dfb66ed7940e43d0524b5911ef034f37dd21c29d16f49bc963f7a1ed57aff5b36a03f9afbcfeb3fe6ccbc5ec5feecd2297df206d735edcf67fbb6f63162ddd6adfd662036ba59cfeb8779d9e1c526dba31ee77b3f0fa4f17e8c2e46d6dd1a2cd65e5eaa4b7767e1fa363116e8bc7bc9ede8640e203dcf20b862738ecc97b2ebe5bcfa369b0b9df8d1873558b39bffab07ffab07ffab07f7f01ffcc021f58a3a50481f06186fdf71a683830bf7c2013376f3ce3ce3785e704eb787ffa00000000000000000000000000000000000007ff79c30ec6f17fb8f13d4e68726abf0ec861379c78279f173df4c7a8ffb5cda2f7fb4fae9eb4b39649f4bcee6c2134a6066f7ea4a6c0e7ef861dbd536bf6e4c5e36e778afb339f78385b3db8cdfbeb0eaab1cf971e1c345df3c3772fd16cc227ffdb830e4e0d73bce7fb968eb77dd375beeffeb1b1fb51fef3646039a54f7fd187d3a44fe38da6d9ea638a6dd0e4616f695b9b6e04d4f7ef8a839292b99fcfbc3351aa3e5ecbe1bfd7af66df67a771338f3c36f8c2791c46486126fb7c3bea6071d0edb66487ad69df3eaf566bf7b37edecfdbc05c326d04df9613db9cfd473eebf8fb6dd5fee42e826d93f41a76f077a8427b4a787623276f7af055361e6fdd2c3663c7a9177fdf1fd71ff0d7ee6fd4ec8f047533a2ef8927d7f87a287317ec86270c95e2d56b91e9778a1a781ce571f9debb773f9ce9243977e267f25b775eedc751f18f4deff7ab853d493e5c1dfa4fecf6e3f6c62a7553bb6ffb8d3929981ba5788cfb6b763f65e1fb76f7e83d7effbbb360bf25537afcf1197260c1f9bfc9b1da37c5b5fedfbb252e9f3df4f793ab7197d68d3875ff7f02fff3018e9891ee0c026c379f7eec3819bccb58597c2edf7b03d7ef06f5fbe17a1ffef3861d8de2ff71e276dcb0e4d57e1d90c3c216704f3e1a3bfee09a52bbc345ed89cb5368e7e53dfda5e2550fe6da3af473f016e2911decff7addeb666367bbc717497f770b40053d39c3df886fddf50dddd8e6f70d7876b85c3df366e5a7a31aa6e4dd8c47c782784d8e1c5fec5ab8f46180e3cd863e744a4c999df40c92ecd94543d7b770a58c1d10ee90db819e587553378215ade0cbfbeffde97eed30e4df5d5268fcb30ddf14b8db543b96f1b1bbea527e3b45f9ff6fbce7e08378fdfa3595be9b29fde5631fee8a3174c1daaddb74c3bc1e1bfdd84eb97761859c9b6b8ddbce6e2c36b3e306a96dcf3d1ecbbe9f55de0b787077366e179ee38dfc1c7965d78eb9cbfb617456f7ee9b37f6f27d75b17ebb1125be7a57fb9b8cb8bf33b68162a3761031bd20249a6f60f7c31db1f1c936bf13a718ff7967f0df3c7d25cd24adfbe9975fff5a65a6596d9ffeb4d01d702f7f7f03ff6f8e9891de086eb8ddf6dd86fe166fb6e60682c804f3375b842fb381aba0ffef3861d8de2ff71e2f37b4439355f876430fabbf98279f07efbfc6e911c5a933178e58eb61bcb831b4c52e1efcac5dc28910c1e6d3b8852f5724670eeff7f98539b23ce6baafc99b173c58f43bfec77ac25edfb37fe4956cefe3cffbdd1fe492b74ebb4f60f47e70c80e218f7e2b2c49e7cd8b9b682667adff726066e83aefabb649c91f3bb83019c6fa769f2e8bd261ccd7e64d792a9ec6b196ad9eb3538b9932fae26631eda77831a7865cb3f8ff61ea277f6d384fee68fd54f72baf4f196693fdd9b38ed4e604c0dad9f241ffd0ff7f04a0bdab4eec1a77e8c5b604a2e05c71a682cb2d32eb8faaede21ea416a4dc4d96977f05ff14b5239a2a466aa0ef11a4b800bccbce11a10023001a65f95d18da081a9230000068a000590024001f75effcc48aae07ff31211703ff98abaae05566e97cd6b20a8418f57fe62426e05c71a682d85a6c2d37ff9415111a4b8171c69a0b2cb4cbae81566e97cd6b20a8418f57fe65b0a5893618745c947420bff9909177320c9b81ffcc8488bdcb526e05566e97cd6b20a8418f577f06a849b7150831eac97e0005e65e708d08011800d32fcae8c6d040d491800003450002c8012000fbaf7f7f079d49ab1cc58273d255440ac731551612d4a8816a1510273d25ac731562d57f089749ab1cc544e7b13016a5440b50a88139e92d6398ab16af7f098f49887a925a9304e7a4aa88158e62ff7f0a99987156398b110e7ea62c05a95102d42a204e7a4b58e62ac5ab7f0b94987110f524b526221cfd4c58273d255440ac73177f0c92ae55864216b4ad40ea9ad1cc580b52dc377f7f0d94b505b22aec2cb1503aa6b473160fe4b52dc377f37f0e93b505b22aec2cb112db2c2d44f507f3c375ffe77f0f90a0684ad21e919aa83c78f0ba4cb90f4f7f10b086eef1a13eb7150831ea829b068aa0f8416a805f145704e94d68544db30aa26c58551362c3e3c785d265c87a551362c37f11ea86eef1a13ea0b4d24056e40cb2129ecd375b525967c4a84c0171c69a0b2cb4d3e20fc5684c0b07e0884c0171c69a0b2cb4d3e20fc548803f15f74c01f8afb991007e133c0f05c0be25c200b2f32e2e15c2b8570ae171c69a0b2cb4db2c8570b8e34d05965a6d9642b87f7f129eafc912881b2908cbe49566657c4b042591618c8e2ceb2d48d3ad34e46d0b7f139f8abf3dcd240d9484148db2b332be258212c8b0c647167596a469d69a7236857f14e58abf321609651392b6195a71a7df65b68ae01e1082e472008f3e269e900f3724840bae9420012571f1be58d91c6013656a4b85f59403e41a08ced9e3fc84daba60169e9b01a37e8068df81ad3ef623253fb28c590daba428c94d1e3985faff6f64739042ff7f15978a625110ed802b8576da642fbec85a5c2e38d34165969c7f16ffa7018abf2cc1295a2b250c8e3ae3f1946cb64948e46379e1ca575a20e495e111f0bcfc8d4607230bc2659702101648e310485b88626e5bff281d489125cac4bb511f779b092863f3f1dcbb76effccd4c60bf8f04a09344dc92847316e28b07bb32ded0f69d3fee463d5fc66877cb7add82a35bc171b9e1820b81000172cda48ef1f61eabbc9e71d94fa91bf9827d9cde43b1e40f327e6dcde38fe653f597c67d7c5228f32779c1b29aaff661ee2d6839326efcbdaafb7d93457400dda4dc76e84720e9cfd2abd778fef83c8ccb567f5674c7c326d0729b07aeb91ee3b71fad0e0aad9daf98f4879836e5f59436c34171de2da3067c41ab0bb9c677fd5e013f7fdd1d365d667ecef672505231d9fbc314def5eec86be7cb574e3f81caf4d66610b87067f698e6820f7f14a3c19f56ce10c18b864bf037804d002eb779b780d60bb76105d002f42de1bd7b05d0e10f408a4148b4a549275a42a13f842d35a7d7408a4148b4a549275a93c85f8321ec47408a4148b4a549275906497f8840e92ac7b0d31aaf4085aec1cd48ff86a8eb10649cbf5886a8eb10649cbf4082497f864d833505b11f00000408000000000f00be0000'))
        #conn.sendall(bytes.fromhex('00000000010000000f'))

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
                            # goway
                            # conn.sendall(bytes.fromhex('0000080700000000000000000000000000'))
                            pass
                        elif frame[3] == 4:
                            # setting
                            if frame[4] == 1:
                                conn.sendall(bytes.fromhex('000000040100000000'))

                        elif frame[3] == 6:
                            #conn.sendall(bytes.fromhex('0000080600000000000000000000000000'))
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
        response.request.raw = msg
        set_cookie = response.headers.get('set-cookie')
        if set_cookie and update_cookies:
            self.handle_cookie(req, set_cookie)

        response.cookies = response.headers.get('set-cookie', {})
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









