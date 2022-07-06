


def default_headers():
    #python-requests/2.25.1
    u = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'text/plain; charset=UTF-8',
        'Connection': 'keep-alive',
    }



def is_ascii(c):
    return True if ord(c) < 128 else False

def urlencoded(s):

    out = ''
    for c in s:
        if is_ascii(c) or c in '!@# $&*()=:/;?+':
           out += c

        else:
            c = c.encode(encoding='utf-8').hex()
            while c:
                out += '%{}'.format(c[:2])
                c = c[2:]
    return out





