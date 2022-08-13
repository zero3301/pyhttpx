# Pyhttpx
基于socket开发的一个网络测试库,供研究https/tls参考,
如果你用过requests,它将会变得非常容易

PyPI:
```
$ python -m pip install requests
```

**安装依赖**

requirement.txt

```
cryptography==36.0.1
rsa==4.8
pyOpenSSL==21.0.0

```

## GET
```
>>> import pyhttpx
>>> sess = pyhttpx.HttpSession()
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies={'k':'3301')
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies='k=3301')
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
>>> r = sess.post('https://httpbin.org/get',json={})
```

## HTTP PROXY
```
>>> proxies = {'https': '127.0.0.1:7890'}
>>> r = sess.post('https://httpbin.org/get',proxies=proxies)
```

## 修改tls指纹

内置ja3

771,49195-49199-52392-52393-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-28,29-23-24-25,0

### 补充说明

**生产环境中,不建议修改密码套件,如果要打乱,应该把49195-49199放在前面,通常情况下服务器会选择第一个套件**

严格意义上的指纹并不是简单的Hash(ja3),而是检测几个关键部分识别的

当然了你也可以添加一些随机数,如果你有足够把握的话


HttpSession 参数说明

tls_ciphers: 密码套件

exts: 扩展类型

exts_payload: 需要填充的扩展数据,不包括数据长度

```
>>>tls_ciphers = [49195, 49199, 52392, 52393, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53]
>>>exts = [0, 65281, 10, 11, 35, 13172, 16, 5, 13, 222]  #222是自定义的随机数类型
>>>exts_payload = {222: '\x01'}
>>>sess = pyhttpx.HttpSession(tls_ciphers=tls_ciphers,exts=exts,exts_payload=exts_payload)
>>>r = sess.get('https://tls.peet.ws/api/all')
>>>r.text
... "ja3": "771,47-49172-52392-53-49200-49195-157-523925,0...
```

# 版本支持

- tls1.2
- http/1.1

# tls密码套件支持

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

有什么bug, 或者好设计模式, 欢迎大家issues</br>

如果对你有帮助,可以请我喝杯咖啡哟

![Image](https://github.com/zero3301/pyhttpx/blob/main/image/wechat.png)
