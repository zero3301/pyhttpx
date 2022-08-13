
import json
import inspect
import platform
import sys
import time

from queue import LifoQueue
import queue
from threading import RLock
import threading
import logging


from urllib.parse import urlencode

from pyhttpx.compat import *
from pyhttpx.models import Request
from pyhttpx.utils import default_headers
from pyhttpx.layers.tls.tls_session import TLSSocket

log = logging.getLogger(__name__)

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
    def __init__(self,req, **kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']

        self.poolconnections = LifoQueue(maxsize=self.maxsize)
        self.lock = RLock()
        self.req = req
    def _new_conn(self, **kwargs):

        conn = TLSSocket(host=self.req.host, port=self.req.port,
            proxies=self.req.proxies, timeout=self.req.timeout,**kwargs)
        conn.connect()

        return conn

    def _get_conn(self, **kwargs):
        conn = None
        try:
            conn = self.poolconnections.get(block=False)

        except queue.Empty:
            pass
        return conn or self._new_conn(**kwargs)

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
    def __init__(self, **kwargs):
        self.tls_session = None
        self.cookie_manger = CookieManger()

        self.active_addr = None
        self.tlss = {}
        self.kw = {}
        self.kw.update(kwargs)
        self.lock = RLock()


    def handle_cookie(self, req, set_cookies):
        #
        if not set_cookies:
            return
        c = {}
        if isinstance(set_cookies, str):
            for set_cookie in set_cookies.split(';'):
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


    def request(self, method, url,update_cookies=True,timeout=None,proxies=None,
                params=None, data=None, headers=None, cookies=None,json=None,verify=False):
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
        self.req = req
        msg = self.prep_request(req, send_kw)
        resp = self.send(req, msg, update_cookies)
        return resp

    def prep_request(self, req, send_kw) -> bytes:
        msg = b'%s %s HTTP/1.1\r\n' % (req.method.encode(), req.path.encode())
        msg += b'Host: %s\r\n' % req.host.encode()
        dh = default_headers()

        dh.update(req.headers)
        dh.update(send_kw)

        for k,v in dh.items():
            msg += ('%s: %s\r\n' % (k ,v)).encode()

        req_body = ''
        if req.method == 'POST':
            if req.data:
                if isinstance(req.data, str):
                    req_body = req.data

                elif isinstance(req.data, dict):
                    # Content-Type: application/x-www-form-urlencoded\r\n
                    # Content-Length: 14\r\n

                    if not b'Content-Type' in msg:
                        msg += b'Content-Type: application/x-www-form-urlencoded\r\n'
                    req_body = urlencode(req.data)


            elif req.json:
                if not b'Content-Type' in msg:
                    msg += b'Content-Type: application/json\r\n'

                req_body = json.dumps(req.json,separators=(',',':'))

            msg += ('Content-Length: %s\r\n' % (len(req_body))).encode()

        msg += b'\r\n'
        msg += req_body.encode()

        return msg

    def send(self, req, msg, update_cookies):

        addr  = (req.host, req.port)
        self.active_addr = addr

        if self.tlss.get(addr):
            connpool = self.tlss[addr]
            conn = connpool._get_conn()
            tls_session = conn

        else:
            connpool = HTTPSConnectionPool(req,host=req.host,port=req.host)
            self.tlss[addr] = connpool
            conn = connpool._get_conn()
            tls_session = conn

        tls_session.send(msg)

        response = tls_session.response
        response.request = req
        response.request.raw = msg
        if response.headers and update_cookies:
            self.handle_cookie(req, response.headers.get('set-cookie'))
        response.cookies = response.headers.get('set-cookie', {})

        self._content = response.content
        if not conn.isclosed:
            connpool._put_conn(conn)

        return response

    @property
    def cookies(self):
        _cookies = self.cookie_manger.get(self.active_addr)
        return _cookies
    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self,url, **kwargs):
        return self.request('POST', url, **kwargs)

    @property
    def content(self):
        return self._content










