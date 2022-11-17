
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


from pyhttpx.models import Response
from pyhttpx.exception import TooManyRedirects
from pyhttpx.utils import vprint

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
    maxsize = 100
    def __init__(self,**kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']
        self.req = kwargs.get('request')

        self.ja3 = kwargs.get('ja3')
        self.browser_type = kwargs.get('browser_type')
        self.exts_payload = kwargs.get('exts_payload')
        self.poolconnections = LifoQueue(maxsize=self.maxsize)
        self.lock = RLock()

    def _new_conn(self):

        context = pyssl.SSLContext(pyssl.PROTOCOL_TLSv1_2)
        context.browser_type = self.browser_type

        context.set_ja3(self.ja3)
        context.set_ext_payload(self.exts_payload)

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


class HttpSession(object):
    def __init__(self, ja3=None, exts_payload=None, browser_type=None):
        self.tls_session = None
        self.cookie_manger = CookieManger()
        self.browser_type = None
        self.active_addr = None
        self.tlss = {}
        self.browser_type = browser_type or 'chrome'
        self.exts_payload = exts_payload
        self.lock = RLock()

        if ja3:
            self.ja3 = ja3
        else:
            if self.browser_type == 'chrome':

                randarr = [6682,19018,64250, 47802]
                self.ja3 = f"771,{randarr[0]}-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,{randarr[1]}-18-65281-27-16-5-13-10-11-0-45-35-51-23-43-{randarr[3]}-21,{randarr[2]}-29-23-24,0"
                self.exts_payload = {47802: b'\x00'}

            else:
                #firefox_ja3
                self.ja3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0"


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
        addr = (req.host, req.port)
        if req.headers.get('Cookie'):
            self.handle_cookie(req ,req.headers.get('Cookie'))

        if cookies:
            self.handle_cookie(req, cookies)

        _cookies = self.cookie_manger.get(get_top_domain(self.req.host))
        send_kw  = {}
        if _cookies:
            send_kw['Cookie'] = '; '.join('{}={}'.format(k,v) for k,v in _cookies.items())

        msg = self.prep_request(req, send_kw)

        resp = self.send(req, msg, update_cookies)
        return resp

    def handle_redirect(self, resp):

        if resp.status_code == 302 and resp.request.allow_redirects:
            location = resp.headers['location']
            for i in range(Conf.max_allow_redirects):
                resp = self.request('GET', location)
                if resp.status_code != 302:
                    break
            else:
                raise TooManyRedirects('too many redirects')

        return resp

    def prep_request(self, req, send_kw) -> bytes:
        msg = b'%s %s HTTP/1.1\r\n' % (req.method.encode(), req.path.encode())
        dh = default_headers()
        dh['Host'] = req.host
        dh['Connection'] = req.headers.get('Connection') or 'closed'

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

        dh.update(req.headers)
        dh.update(send_kw)

        for k, v in dh.items():
            msg += ('%s: %s\r\n' % (k, v)).encode('latin1')

        msg += b'\r\n'
        msg += req_body.encode('latin1')
        vprint(msg.decode())
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
                                           exts_payload=self.exts_payload,
                                           browser_type = self.browser_type,

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









