
import json
import inspect
import platform




from urllib.parse import urlencode

from pyrequests.compat import *
from pyrequests.models import Request
from pyrequests.utils import default_headers

if platform.system().lower() == 'linux':
    from pyrequests.layers.tls.linux.tls_session import TlsSession
else:
    from pyrequests.layers.tls.window.tls_session import TlsSession


#from pyrequests.layers.tls.tls_session import TlsSession


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

class HttpSession(object):
    def __init__(self):
        self.tls_session = None
        self.cookie_manger = CookieManger()
        self.active_addr = None
        self.tlss = {}


    def handle_cookie(self, req, set_cookies):
        #
        if not set_cookies:
            return
        c = {}
        if isinstance(set_cookies, str):
            for set_cookie in set_cookies.split(';'):
                k, v = set_cookie.split('=', 1)
                c[k] = v
        elif isinstance(set_cookies, list):
            for set_cookie in set_cookies:
                k, v = set_cookie.split(';')[0].split('=', 1)
                c[k] = v
        elif isinstance(set_cookies, dict):
            c.update(set_cookies)
        self.cookie_manger.set_cookie(req,c)


    def request(self, method, url,
                params=None, data=None, headers=None, cookies=None,json=None):
        req = Request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            data=data or {},
            json=json,
            cookies=cookies or {},
            params=params or {},
        )
        addr = (req.host, req.port)

        if req.headers.get('Cookie'):
            self.handle_cookie(req ,req.headers.get('Cookie'))

        if cookies:
            self.handle_cookie(req, cookies)

        _cookies = self.cookie_manger.get(addr)

        send_kw  = {}
        if _cookies:
            send_kw['Cookie'] = ';'.join('{}={}'.format(k,v) for k,v in _cookies.items())
        self.req = req
        msg = self.prep_request(req, send_kw)
        resp = self.send(req, msg)
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
                    req_body = req.data.encode()

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

    def send(self, req, msg):


        addr  = (req.host, req.port)
        self.active_addr = addr
        if self.tlss.get(addr):
            self.tls_session = self.tlss[addr]
        else:
            self.tlss[addr] = TlsSession()
            self.tls_session = self.tlss[addr]
        if self.tls_session.isclosed:
            self.tls_session.connect(host= self.req.host, port= self.req.port)

        if not self.tls_session.isclosed:
            #self.tls_session.get(self.req.path, self.req.host)
            result = self.tls_session.send(msg)
            if not result:
                #报错
                del self.tlss[addr]
                return self.send(req, msg)
            response = self.tls_session.response
            response.request = req
            response.request.raw = msg
            if response.headers:
                self.handle_cookie(req, response.headers.get('Set-Cookie'))
            response.cookies = response.headers.get('Set-Cookie', {})
            return response

    @property
    def cookies(self):
        _cookies = self.cookie_manger.get(self.active_addr)
        return _cookies
    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)


    def post(self,url, **kwargs):
        return self.request('POST', url, **kwargs)

    def close(self):
        self.tls_session.socket.close()

    @property
    def content(self):
        return self.tls_session.response.content
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.tls_session.socket.close()

    def __del__(self):
        if hasattr(self, 'tls_session') and self.tls_session:
            self.tls_session.socket.shutdown(1)
            self.tls_session.socket.close()

if __name__ == '__main__':
    import pprint
    import time
    sess = HttpSession()
    url = 'https://httpbin.org/get'
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36",}
    r = sess.get(url,headers=headers)
    print(r.text[:200])








