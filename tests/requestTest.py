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
'Host': 'ccie.cloudapps.cisco.com',
'Pragma': 'no-cache',
'Cache-Control': 'no-cache',
'sec-ch-ua-platform': '"Windows"',
'sec-ch-ua-mobile': '?0',
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
#'Content-type': 'application/x-www-form-urlencoded',
'Accept': '*/*',
'Sec-Fetch-Site': 'cross-site',
'Sec-Fetch-Mode': 'cors',
'Sec-Fetch-Dest': 'empty',
'Accept-Encoding': 'gzip, deflate, br',
'Accept-Language': 'zh,zh-CN;q=0.9,en;q=0.8',
}


def main():
    #默认开启http2
    #tls1.2
    ja3='771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0'
    sess = pyhttpx.HttpSession(http2=False,
                               #ja3=ja3,
                               browser_type='chrome')

    url='https://tls.peet.ws/api/all'
    #url = 'https://httpbin.org/get'

    r = sess.get(url,headers=headers,
                 allow_redirects=True,
                 )
    print(r.status_code)
    print(r.text)

if __name__ == '__main__':
    main()























