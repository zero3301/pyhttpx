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
'Connection': 'keep-alive',
'Pragma': 'no-cache',
'Cache-Control': 'no-cache',
'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
'sec-ch-ua-platform': '"Windows"',
'sec-ch-ua-mobile': '?0',
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
'Content-type': 'application/x-www-form-urlencoded',
'Accept': '*/*',
'Sec-Fetch-Site': 'cross-site',
'Sec-Fetch-Mode': 'cors',
'Sec-Fetch-Dest': 'empty',
'Accept-Encoding': 'gzip, deflate, br',
'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8',
}


def main():
    #默认开启http2
    sess = pyhttpx.HttpSession(http2=True, browser_type='chrome')
    url='https://tls.peet.ws/api/all'
    r = sess.post(url,headers=headers)
    print(r.status_code)
    print(r.text)
if __name__ == '__main__':
    main()























