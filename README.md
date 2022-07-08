# Pyrequests
基于socket开发的一个网络测试库,供研究https/tls参考,
如果你用过requests,它将会变得非常容易, 内置firefox34版本指纹

**安装依赖**
测试版本python3.7.5
requirement.txt
```
cryptography==36.0.1
```

## GET
```
>>> import pyrequests
>>> sess = pyrequests.HttpSession()
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies={'k':'3301')
>>> r = sess.get('https://httpbin.org/get',headers={'User-Agent':'3301'},cookies='k=3301')
>>>r.status_code
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
## JA3
目前支持仅0,65281,10,11,35,13172,16,5,13扩展,如果想修改指纹,可以扩展打乱,不要额外的添加指纹标识,以免出现bug
```
>>>ja3 = [0,65281, 10 ,11,35,13172,16,5,13]
>>>random.shuffle(ja3)
>>>sess = HttpSession(ja3=ja3)
>>>r=sess.get('https://ja3er.com/json')
>>>r.text
{"ja3_hash":"e351719fcbcc6f320753284e9c921f5f", "ja3": "771,49195-49199,0-65281-10-11-35-13172-16-5-13,23,0",...
```

# 相关功能支持
- tls1.2
- 密码套件TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
- http/1.1

# 关于pyrequests
时间充足的话,后面考虑添加代理,动态tls指纹,tls1.3,http2</br>
有什么bug, 或者好设计模式, 欢迎大家issues</br>
本人vx号: ZanCoder,如果感兴趣和我一起学习开发吧

### 附录tls相关资料
   [tls1.2](https://www.rfc-editor.org/rfc/rfc5246.html)  
   [tls1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
 


