

def default_headers():
    h = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',

    }

    return h


class Conf:
    debug = True

def vprint(*args):
    if Conf.debug:
        print(*args)



