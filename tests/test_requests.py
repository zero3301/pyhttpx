import pyhttpx
import time
import json
from pprint import pprint as pp
import time
import random

if __name__ == '__main__':

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
    headers = {
        "User-Agent": ua,

    }
    url = 'https://tls.peet.ws/api/all'
    url = 'https://127.0.0.1'

    tls_ciphers = [49195, 49199, 52392, 52393, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53,55]
    sess = pyhttpx.HttpSession(tls_ciphers=tls_ciphers)
    #random.shuffle(tls_ciphers)
    exts = [0, 65281, 10, 11, 35, 13172, 16, 5, 13]
    exts_payload = {222: '\x01'}
    r = sess.get(url,)

    print(r.status_code)
    pp(r.text)











