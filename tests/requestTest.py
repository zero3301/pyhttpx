import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random

import concurrent
import threading
import requests

headers = {
"Connection": "keep-alive",
"Cache-Control": "max-age=0",
"sec-ch-ua": "\"Chromium\";v=\"106\", \"Google Chrome\";v=\"106\", \"Not;A=Brand\";v=\"99\"",
"sec-ch-ua-mobile": "?0",
"sec-ch-ua-platform": "\"Windows\"",
"Upgrade-Insecure-Requests": "1",
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
"Sec-Fetch-Site": "none",
"Sec-Fetch-Mode": "navigate",
"Sec-Fetch-User": "?1",
"Sec-Fetch-Dest": "document",
"Accept-Encoding": "gzip, deflate, br",
"Accept-Language": "zh,zh-CN;q=0.9,en;q=0.8",
"context-type": "application/x-www-form-urlencoded"
}


def main():
    url = 'https://tls.peet.ws/api/all'
    sess = pyhttpx.HttpSession(browser_type='chrome')
    r = sess.get(
        url, headers=headers,
    )
    pp(r.json)



if __name__ == '__main__':

    main()

























