import logging
from collections import defaultdict

from urllib3.util import parse_url
from requests.utils import prepend_scheme_if_needed
from requests.exceptions import InvalidProxyURL


def _parse_proxy_url(proxy_url):
    proxy_url = prepend_scheme_if_needed(proxy_url, "http")
    parsed_proxy_url = parse_url(proxy_url)

    if not parsed_proxy_url.host:
        raise InvalidProxyURL(
            "Please check proxy URL. It is malformed" " and could be missing the host."
        )

    return parsed_proxy_url

class IgnoreCaseDict(defaultdict):
    #忽略key大小写
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._keys = {}

    def __delitem__(self, key):
        super().__delitem__(key)

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):

        k = self._keys.get(key.lower())
        if k and k != key:
            self.__delitem__(k)

        super().__setitem__(key,value)
        self._keys[key.lower()] = key

    def update(self, d ,**kwargs) -> None:
        for k, v in d.items():
            self.__setitem__(k ,v)

    def get(self, key):
        k =self._keys[key.lower()]
        return super().__getitem__(k)

def default_headers():
    h = {
    'Host': '*',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
    'sec-ch-ua-platform': '"Windows"', 'sec-ch-ua-mobile': '?0',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8'
}
    d = IgnoreCaseDict()
    d.update(h)
    return d

log = logging.getLogger(__name__)

class Conf:
    debug = False
    max_allow_redirects = 5

def vprint(*args):
    if Conf.debug:
        print(*args)




