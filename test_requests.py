import pyrequests


sess = pyrequests.HttpSession()

r = sess.get('https://httpbin.org/get')

print(r.text)



