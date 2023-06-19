import re

import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random
import os
import concurrent
import threading
import requests

headers={
'Host': '*',
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
'Pragma': 'no-cache',
'Cache-Control': 'no-cache',
'sec-ch-ua-platform': '"Windows"',
'sec-ch-ua-mobile': '?0',
'Accept': '*/*',
'Sec-Fetch-Site': 'cross-site',
'Sec-Fetch-Mode': 'cors',
'Sec-Fetch-Dest': 'empty',
'Accept-Encoding': 'gzip, deflate, br',
'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8',

}


def main():
    sess = pyhttpx.HttpSession(http2=False,
                               browser_type='chrome',
                               )

    url='https://tls.peet.ws/api/all'
    #url = 'https://httpbin.org/ip'
    proxies = {
        'https': 'http://username:password@host:port'
    }
    r = sess.get(url,headers=headers)
    print(r.status_code)
    print(r.text)

if __name__ == '__main__':
    main()























