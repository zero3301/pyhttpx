# Pyhttpx
基于socket开发的一个网络库,供研究https/tls参考
如果你用过requests,它将会变得非常容易

# 版本协议支持
- tls1.2/tls1.3
- h1/h2

PyPI:
```
$ python -m pip install --upgrade pip
$ python -m pip install pyhttpx
```

**安装依赖**

requirement.txt

```
cryptography==36.0.1
rsa==4.8
pyOpenSSL==21.0.0

brotli==1.0.9
hpack==4.0.0
```




## GET
```
>>> import pyhttpx
>>> sess = pyhttpx.HttpSession()
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies={'k':'3301')
>>> r.status_code
200
>>> r.encoding
'utf-8'
>>> r.text
'{\n  "args": {}, ...
>>> r.json
{'args': {},...

```
##### 如果你想知道原生http报文是否达到预期,你可以这样
```
>>> r.request.raw
b'GET /get HTTP/1.1\r\nHost: httpbin.org ...
```

## POST
```
>>> r = sess.post('https://httpbin.org/get',data={})
```

## HTTP PROXY
```
>>> proxies = {'https': 'http://username:password@host:port'}
>>> r = sess.post('https://httpbin.org/get',proxies=proxies)
```

## ALLOW_REDIRECTS

  ```
>>> r = sess.post('https://httpbin.org/get',allow_redirects=True)
```  



# 支持ssl上下文

如果数据是空字符,表示收到fin,服务器断开连接

```
>>>from pyhttpx.layers.tls.pyssl import SSLContext,PROTOCOL_TLSv1_2
>>>import socket
>>>addres = ('httpbin.org', 443)
>>>context = SSLContext(PROTOCOL_TLSv1_2, http2=False)
>>>sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
>>>ssock = context.wrap_socket(sock, server_hostname=addres[0])
>>>ssock.connect(addres)
>>>m = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % addres[0]
>>>ssock.sendall(m.encode())
>>>r = ssock.recv()
b'HTTP/1.0 200 OK\r\n'...
```

# websocket

    参考文档tests/test_websockt.py
    


# tls密码套件支持
- TLS13_AES_128_GCM_SHA256(0X1301)
- TLS13_AES_256_GCM_SHA384(0X1302)
- TLS13_CHACHA20_POLY1305_SHA256(0X1303)
- ECDHE_WITH_AES_128_GCM
- ECDHE_WITH_AES_256_GCM
- ECDHE_WITH_CHACHA20_POLY1305_SHA256
- RSA_WITH_AES_128_GCM
- RSA_WITH_AES_256_GCM
- RSA_WITH_AES_128_CBC
- RSA_WITH_AES_256_CBC
- ECDHE_WITH_AES_128_CBC
- ECDHE_WITH_AES_256_CBC


### 附录tls相关资料

   [tls1.2](https://www.rfc-editor.org/rfc/rfc5246.html)  
   [tls1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
 
### end

