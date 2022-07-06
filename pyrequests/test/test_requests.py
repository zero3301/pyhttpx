import pyrequests


sess = pyrequests.HttpSession()

r = sess.get('https://httpbin.org/get',headers={'UA':'UA'},cookies='a=2&c=3')
r = sess.post('https://httpbin.org/get',json={'name': '3301'})
print(r.request.raw)



