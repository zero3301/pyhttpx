
import pyrequests
import pprint
sess = pyrequests.HttpSession()
import requests
import json
import time

cookie = 'ti_geo=country=CN|city=GUANGZHOU|continent=AS|tc_ip=113.89.245.150; ti_rid=4625fb6; ti_ua=Mozilla%2f5.0%20(Windows%20NT%2010.0%3b%20Win64%3b%20x64%3b%20rv%3a102.0)%20Gecko%2f20100101%20Firefox%2f102.0; ti_bm=; _abck=0C375A72DA9A411B0AA9D7DF8738229E~-1~YAAQ5G+bG2bOi7mBAQAAYMeOxwiSNC50suDauswyW27bN0w/0tPE3QSFlJ8PjH7alKLtGot1bY/9UjRS+B5a3ovvnQ+Ce44TgnELE+/zpTta5u4z2SfP6237h6t1qY17HC8HygxhvHBsmvulg3UMccSqYB4Yl3/HM8KlSiGuvfZzrR+exhSmeMNcxjfv5TigQWmPYCNmykEAI8OnY39TIO+x9U8UsVkjLT6ONl6RV7QybOJsYgjURfEtXsyEshJqFKfXBPi8oOCTshin6Zk8TmSuDgVHCn/L+ehDbsVtoq0+qIjonsbUSAdZpJL4hT0c00rkthtg764WldsqfpNp2y+18Sax/RoQRN2K6pZroWIHfVVARLaZyGOrI5xmubfQHFqmzNHuNSgUZjyqUy2AklLCcWXSgg4ZCQ+PgvYvYLydS+HdI7OFS6XzxUacEIgnJEmemWGZm1SOumHlouQBKj8wsZxjrG1jWwy4~-1~-1~-1; ak_bmsc=9184D735FAA69E508FC3375573FCB70A~000000000000000000000000000000~YAAQ5G+bG1SNfrmBAQAAEM9IxxBpLXXUef8AZqPT3M83Xp2yRUrE7fAvo6EbCOFsfCsRgwhcDQNB24meua4X3EmIbGDPIXHXPCUFa1o9iVj/fZ+4qz6Ln06xqHpljxbdcPPFvO36d3UONG51KydhedVeWcLFBo4b3fyNZeWNDjnj5rah/9HHtr/53fJWRn6nucY0LXy7Ta1pda4p+plhEPqbY5uXLeRZkyPAOTMwOgnMgIoqMhJShLu1TfNdtHcM5EhDfkjCckO2/sk53Ky8U68iV3rc1/85vbdOWxlS+G4U2cYR1iZba8XFIxyWK//JaVuSOpt5aN+E6ZAcRGpLAXYPlWs+Fz45ziYSfi1Qdje0Q7/ZYTWSnVfQsL0qXgfg4RIkVzxtM6mJzI3xyDZ5cg3fw+5LkdDYRWrd8nPS7sO2WxuV/MsdbbbHf1M6rxkOMx9SL0jrIDxblhU+v5yHU4FJX5y6Kqro4NxZSlA2vTm2wl22zEMGgIGt2QZJdV4=; bm_sz=DD66D0B20E5425601BD753987282F3AC~YAAQ5G+bGznLfLmBAQAA8AhBxxDztj1y0gNf8Hnf8whkjYiThnQnWbUaIlbv3dTm511R9we5cZRd8WXjEQXSHS7PidICdWQxrAsUwC57zFDpF+S4uEzj2mbNBC4JcvQK09+0Qf+gRv/6iaaZr+HeARVmwzA9yM6rUgC0LS/dY3o8zByRcdbiwQa9KZ1cljMrFQmXtN0YiGv7UU9Xn15BFiRYHUgcc7J86ClJAMWMxx9YVqGGiQfvd2YvhQrjqi7Gd+oHeQQmgwj3t6TT3aK/QDuhym/1CyOngA3rdZhb2hMNWIEiks35uhp76ROzVuUBKFFiB9t4HkULxbDh4ehH+MzdtXQv0FlpNZGmVo58fADn6YzrJjVLKVDyGikCVf9nI51S6yIKHxe5CwFHC7Dkdx/lnZ87fWNTJBkfsff6UsR/ACjZQg==~3425335~3158072; bm_mi=790B2F40613FA5EF8BE75368E592488B~YAAQ5G+bG+/bdrmBAQAA+KklxxDLz/jTCHiP35Fy0176GRbVgzUtq/tLA+7GM9f3gaDj8KtCPUQNmhXlxEspUvbn9foSd5oMtqyzVu6EH7pWiPKjU6Ewufm7D+2gVYpYMxl6p9RX7mG1ejRktyTnONjlTvBX3r79C5EweWurBp2F/rHquQs0NhGNY9HespR8QQ5SngEM86NpeCAu3fDMb6LaOETAvGnEc8s4mAmeAeelOyDYgmdCRwJW18OUBOb53GE+90xdB8Gf9n3c1liZRX4DYD1AxK8i12/zzDkHAmWxzX7T2BnYM31EtO443xj+fa9uQg==~1; bm_sv=F1EAB7AF1E4C5968A42493E0AF6BC494~YAAQ5G+bG2fKi7mBAQAAka2OxxCoBtcDqy1/lf58Kk0q8wBStPrRTV6FA4Oxq5oJsp39GfmwWg8TDxfMKBH5pvr6983rnFga6wzsmckVT7XhsBrD+kpiLYJp84p+Og1kD2C5eQo/HBK5gVsXP3lFmDnHccJCyQtKlkBZ005vqLEk+lhs4P1GjqDuL6E5dwL8EOckTnNdclagFoqDaeUxyNd0nnVg7+zd0+/nBse5aAObiWjdWaDrPYrXU0by~1; CONSENTMGR=ts:1656903543160%7Cconsent:true; utag_main=v_id:0181c725a9790012e5e6829c35c105050004f00d00c98$_sn:1$_ss:0$_pn:6%3Bexp-session$_st:1656912230955$ses_id:1656903543161%3Bexp-session$free_trial:false$dc_visit:1$dc_event:8%3Bexp-session$dc_region:ap-northeast-1%3Bexp-session; tiSessionID=0181c725a9790012e5e6829c35c105050004f00d00c98; alias=homepageproduct; tipage=%2Fanalog%20%26%20mixed-signal%2Famplifiers%2Foperational%20amplifiers%20(op%20amps)%2Fprecision%20op%20amps%20(vos%3C1mv)%2Fopa4h014-sep%2Fproduct%20folder-opa4h014-sep-en; tipageshort=product%20folder-opa4h014-sep-en; ticontent=%2Fanalog%20%26%20mixed-signal%2Famplifiers%2Foperational%20amplifiers%20(op%20amps)%2Fprecision%20op%20amps%20(vos%3C1mv)%2Fopa4h014-sep; ga_page_cookie=product%20folder-opa4h014-sep-en; ga_content_cookie=%2Fanalog%20%26%20mixed-signal%2Famplifiers%2Foperational%20amplifiers%20(op%20amps)%2Fprecision%20op%20amps%20(vos%3C1mv)%2Fopa4h014-sep; pf-accept-language=en-US; last-domain=www.ti.com; user_pref_givenName=""; user_pref_language="en-US"; user_pref_currency="USD"; pxcts=445b6750-fb45-11ec-a2ea-4b55466c454a; _pxvid=445b5c51-fb45-11ec-a2ea-4b55466c454a; _pxde=26c85db86fdc5231d70f8f5d2322f548de61f09b276f22c924f23a631de2b7ce:eyJ0aW1lc3RhbXAiOjE2NTY5MTA0MjIyNjMsImZfa2IiOjAsImlwY19pZCI6W119; ABTasty=uid=4a4f0dr258vxce0j&fst=1656903545115&pst=-1&cst=1656903545115&ns=1&pvt=6&pvis=6&th=684039.848371.4.4.1.1.1656903605528.1656905848326.1_816192.1013836.6.6.1.1.1656903546665.1656905848301.1; _ga=GA1.2.1420472981.1656903546; _gid=GA1.2.989118007.1656903546; _px2=eyJ1IjoiYTAzNTFkYjAtZmI0YS0xMWVjLTgwYTYtMDkyZTRhYzliZWZjIiwidiI6IjQ0NWI1YzUxLWZiNDUtMTFlYy1hMmVhLTRiNTU0NjZjNDU0YSIsInQiOjE2NTY5MTA3MjIyNjIsImgiOiI0ODk5Y2I0YzMxNDQ5ODYwNzJjNTQwMzk4MTlmOWU4NDRmODMwOWQ2NGRjNjk3MjI1MDI0M2ZjYWYxOWU0ZmE0In0=; ti_ai=%7C%7C3258499%7C10208917%7CX; chipset=10208917; user_pref_givenName=DB; login-check=null; auth_session=TXWAvjo6_KwZ1frI.TZjTFojxATiqHMs3MXWItGa_7U_sDVek9sxhVIIIWKAMqkpbC9Z5RB2RB5h417A8FJt8d1KbKMy5e1OQQx0kKb5nTB6XMuGbZoIELMuXrEObotNGWWWCB9Z1XgiiA9D98CULULn1p7V_yr4sWm3sPaGKzVU8u6jLdf5f6Inh-iWOXNlquHb58SgsOuQLoGe4x6taGTwJ7uhmQtL19QCU16i1dhJEjfbCBEfP3ysULIj_i8JGQg07runbfc0AcAZWv8d-4yF4cscCAOlhsIWLc6CiBQqZ6lD9v4O-aM8OcDZE8zWfouCz8ZB5W0v0DuZNMxxgc240yuxQhe5bKBYa2Dyy5tenj3CuqIaU7X2kMk-KHV6JPpPDtgIpBdYnMI3-vzCP_h_iMtPoVrrkoTdAhBQuxEb5v9WTjm8J7qDbBjOWKAthWA5cNpDJqRGm5z64e4S3XWuLlo4LkBpAfQ-fqHzwy7QuN-0xwGnDqPtwd-0kC42yC61oGt06t7D6OkHlGi1q9A5GseGce72IS1oW-ZA5taDAb4qcOTYY2oAqEj_D-eq7E1GTim0zSnB9Nfs6JTRy0XVYT9ol72oS69lhBxCi8jn0GwVZfxyp3W7pVisrj3hQ73vc01Eof-pvmJ2AMQkqEhfIsqM4q8H5a00STjcrOEiIyq7FJ1rOcScpeySDuxHT9YIbnlUHDOhNWNfHYhKzR4-tT1SbrUWRQscmUtgdu-m-bbuacj9YurvxdZMkC4fPffn7iq6WFnF96LjLA-syUdBlibLHKeIFqHx3BuwXo51CaLG7S7iAPi_sU1JpH4YCi7rnXkk8GBzVh_qRX3ui5Sw2ivtvVKzu_YTwO1bWVzdD58jHbt2ta1MpjopINxI84mqq2vRelbTfe7xtlcqUufiUZPvTd8wajML1afp2EzEI5w5CLE0qpkpmMf2VuzISQzq8RBJFBEHrO1fmjWuhY6Lbv1FZVXiFkoRWJlEJAc6OS6k7RWB5ULed2m3ZncKuPt-HvAUmBsFwvDcglRnxYzEFO6bSR5f3Mp4XDKIZk6vlJSXfcrzF7sLQIevqHTaecniMEeLSazi7FM7gLGZJLYRWMrUJQ0p5-mX6KszROUHDdbuDZRXgdI-5juGYxt_BGjWCXjowJ1flyCwLwAgFtsSCEB5lEWTZMgFAS8fo_CMTgG6EO0dWPl7CooHduSYuSmRdSFg-ULaDA-rb1xsDaqnw4kI0cu2scwqZz9oKwYs527yZLmGOwcyLEdG00J48IysxBpAxA3h21RC4yLmJj1xQ1DbCczxpjCP8YZSt40cUU4s9vQWlk4WKkLm9I_B3YYVxaLC4B13BGMl4uEsXl9HXnWFDij2ocCuiQwPSnffVgYjpbTjbWlUsAxUi7ZLv6L58eJWTg_3E0TzqXnEeQsqmAVHseHGQtK0vfMo4n-bwgSAz-SnFv4MIkkEWrCRuvrgRV0KM6YzyXPqNhN86Maqk6hQk03v1ykXCtOVBHysxNYQ8gThX81Lt7fxlrTRr4RuWUbhniqFKt9zKre1b89pYje5BL-YByxRrSWESH0jdJ1lAzvZkLwfmCcGW2GK8QzV3DrBqZROddzAKxpU5euXhoW7mmzZEuG5vJMh4ihOJRq8Cey0guCtb3Q6xmUMYXKuaECOCBvE7h8sIz-RVNtnOOf8OvKnxyhgRYZkI8b1vxb7KhqeVxoLBDMvUOzopJAeld4oKBWBRiLDfiN7u7WejvDuQHibpSqxF4qZCadi156NuTcl2LAfF9c63Pa-tBHuZQ-Ev-vFq8wA6RchwfLNPWkGmdvdWZfT-pZ1MXaDU2rEJCuXJCHik.JuOsSyoJAwMRpcTb5ycsSw; _gcl_au=1.1.134376739.1656903607; ELOQUA=GUID=83F81CAA437145A891329CC4E1887FA8; da_lid=6F461C239A73EA1A824DBB99F67B9BFDFF|0|0|0; userType=Registered; _gat_ga_main_tracker=1'
headers = {

'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
'Accept': '*/*',
'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
'Accept-Encoding': 'gzip, deflate, br',
'Referer': 'https://www.ti.com/product/OPA4H014-SEP?jktype=homepageproduct&login-check=true',
'Origin': 'https://www.ti.com',
'Connection': 'keep-alive',
'Cookie': cookie,
'Sec-Fetch-Dest': 'empty',
'Sec-Fetch-Mode': 'no-cors',
'Sec-Fetch-Site': 'same-origin',
'TE': 'trailers',
'cache-control': 'no-store, must-revalidate, no-cache',
'content-type': 'application/json',
'expires': '0',
'newrelic': 'eyJ2IjpbMCwxXSwiZCI6eyJ0eSI6IkJyb3dzZXIiLCJhYyI6IjE3MjA1OTQiLCJhcCI6IjEzMDkxOTg1NzgiLCJpZCI6IjFjMTQzYjBjZmJhZDZiOTAiLCJ0ciI6ImVlMDY2ZmFkM2M1NjdiYjA2OGNkNDYzOWU3MDY2NzEwIiwidGkiOjE2NTY5MDc4MDI1OTUsInRrIjoiMTU2NTEzNiJ9fQ==',
'traceparent': '00-9a4b7acd7ce61ebd242d6db3604facc0-e27bf17a8a5965a2-01',
'tracestate': '1565136@nr=0-1-1720594-1309198578-e27bf17a8a5965a2----1656901769257',
'x-sec-clge-req-type': 'ajax',
'Pragma': 'no-cache',

}

data  ={"cartRequestList":[{"packageOption":None,"opnId":"OPA4H014PWSEP","quantity":"1","tiAddtoCartSource":"ti.com-productfolder","sparam":""}],"currency":"USD"}
url = 'https://www.ti.com/occservices/v2/ti/addtocart'
#url = 'https://httpbin.org/post'
#url = 'https://www.ti.com/'
sess2 =requests.session()
while 1:
    r = sess.post(url, headers=headers,json=data)
    print(r.text)

    # r = sess2.post(url, headers=headers,json=data)
    # print(r.text)
    time.sleep(60)


# sess2 =requests.session()
# r = sess2.post(url, headers=headers,json=data)
# print(r.text)



