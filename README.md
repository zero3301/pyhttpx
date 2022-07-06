## pyrequests
一个简单https网络请求库,作为个人学习记录,暂不支持代理,如果你用过requests,它将会变得非常容易

安装依赖
```
cryptography==36.0.1
pyOpenSSL==21.0.0
```

#GET
```
>>> import requests
>>> r = requests.get('https://httpbin.org/basic-auth/user/pass', auth=('user', 'pass'))
>>> r.status_code
200
>>> r.headers['content-type']
'application/json; charset=utf8'
>>> r.encoding
'utf-8'
>>> r.text
'{"authenticated": true, ...'
>>> r.json()
{'authenticated': True, ...}
```
