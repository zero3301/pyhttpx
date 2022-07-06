# Pyrequests
一个简单https网络请求测试库,作为个人学习记录,暂不支持代理,如果你用过requests,它将会变得非常容易, 内置firefox34指纹.

**安装依赖**
requirement.txt
```
cryptography==36.0.1
pyOpenSSL==21.0.0
```

## GET
```
>>> import pyrequests
>>> sess = pyrequests.HttpSession()
>>> r = sess.get('https://httpbin.org/get',headers={'ua':'3301'},cookies={'k':'3301')
>>> r = sess.get('https://httpbin.org/get',headers={'ua':'3301'},cookies='k=3301')
>>>r.status_code
200
>>> r.headers['content-type']
'application/json; charset=utf8'
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
>>> r = sess.post('https://httpbin.org/get',json={})

```

# 相关功能支持
- tls1.2
- 密码套件TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
- http/1.1

# 关于pyrequests
后期考虑添加代理,动态tls指纹,tls1.3,http2
有什么bug, 或者好设计模式, 欢迎大家issues
本人vx号: ZanCoder,如果感兴趣和我一起学习开发吧

