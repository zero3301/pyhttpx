import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random
import requests

if __name__ == '__main__':

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    headers = {
        "User-Agent": ua,

    }

    url = 'https://tls.peet.ws/api/all'
    url = 'https://127.0.0.1'

    proxies = {
        'https': '127.0.0.1:7890'
    }

    proxies = {}
    tls_ciphers = [49195, 49199, 52392, 52393, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53]
    random.shuffle(tls_ciphers)
    exts = [0, 65281, 10, 11, 35, 13172, 16, 5, 13, 222]
    exts_payload = {222: '\x01'}
    sess = pyhttpx.HttpSession(tls_ciphers=tls_ciphers,exts=exts,exts_payload=exts_payload)
    #r = sess.get(url, proxies=proxies)

    #print(r.json)
    t1 = time.time()
    for i in range(300):
        r = sess.get(url, proxies=proxies, verify=False)
        #print(r)

    print(time.time() -t1)








