
import pyrequests
import pprint
sess = pyrequests.HttpSession()
import requests
import json
import time
from pyrequests.abck import make_abck
import re
def arr_to_str(start_time, _abck):
    arr = []
    arr.append('7a74G7m23Vrp0o5c9354891.75')
    arr.append(
        '-100,Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0,uaend,2867,20100101,zh-CN,Gecko,6,0,0,0,407697,6707819,2048,1112,2048,1152,1429,281,1442,,cpen:0,i1:0,dm:0,cwen:0,non:1,opc:0,fc:1,sc:0,wrc:1,isc:182.39999389648438,vib:1,bat:0,x11:0,x12:1,5143,0.914907589457,828493353899,0,loc:'
    )
    arr.append('-131,')
    arr.append(
        '-101,do_en,dm_en,t_dis'
    )
    arr.append(
       '-105,0,0,0,0,1037,1037,0;0,0,1,0,1075,1375,0;0,0,1,0,1204,1504,0;-1,-1,1,0,-1,-1,0;-1,-1,1,0,-1,-1,0;-1,0,0,0,-1,686,0;-1,0,0,0,-1,936,0;-1,0,0,0,-1,415,0;'
    )
    arr.append(
        '-102,0,0,0,0,1037,1037,0;0,0,1,0,1075,1375,0;0,0,1,0,1204,1504,0;-1,-1,1,0,-1,-1,0;-1,-1,1,0,-1,-1,0;-1,0,0,0,-1,686,0;-1,0,0,0,-1,936,0;-1,0,0,0,-1,415,0;'
    )
    arr.append('-108,')
    arr.append('-110,')
    arr.append('-117,')
    arr.append('-111,')
    arr.append('-109,')
    arr.append('-114,')
    arr.append('-103,')
    arr.append('-112,https://www.ihg.com.cn/hotels/cn/zh/reservation')
    hg115 = [
        '-115',1, 32, 32, 0, 0, 0, 0, 24, 0, 1656986707798, -999999, 17725, 0, 0, 2954, 0, 0, 60, 0, 0,
        'A03DC7D61D3A010007437F49D72A9E37~-1~YAAQHoyUG21GDJOBAQAAeY8azAg0R + S / Ce9WkKrAktElYCMMrjhOiGhUZE4PNA / WVH + sJTT0Fh3FXxT01 / yyxF885LXJhi7 + 6O7BosmNpnsQOISgYdY7HOJ3qeGrQdAgZvGc4TS4i4j6GrO0BDGX6p / J3EaUePL3GrLv3itPBbACN / 9pDbNf + kthAww14AAW + uBtgk3tSXB30SBgnUjuPB491X1X5fxaZieMeCdfEXRg0wdoJmm7mVs / hRH0F + qmhSE8FJGkQT8I9uss7AsWgpXSz8zL8ZEKADUZda9n + rmhF / MwbZHSGrcvRisrR6UUU2rti9McYO6xdZwlu8NLAxYJk4mBw7MZWRpGJMtU9axYhJSPXS6SISb9oIeM / K4 / Kf2do + sQruOcaW8 = ~-1~-1~-1', 36122, -1, -1, 25462832, 'PiZtE', 22351, 63, 0, -1

    ]
    #10
    #21
    hg115[10] = str(start_time)
    hg115[21] = _abck

    hg115 = [','.join(map(lambda i:str(i),hg115))]
    arr += [','.join(hg115)]
    arr += ['-106,0,0']
    arr += ['-119,-1']
    arr += ['-122,0,0,0,0,1,0,0']
    arr += ['-123,']
    arr += ['-124,']
    arr += ['-126,']
    arr += ['-127,6']
    arr += ['-70,-1']
    arr += ['-80,94']
    arr += ['-116,181111413']
    arr += ['-118,97009']
    arr += ['-129,']
    arr += ['-121,;38;-1;0']

    join_str = '-1,2,-94,'


    s = f'{join_str}'.join(arr)
    print(s)
    return s

chrome_headers={

'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
'accept-encoding': 'gzip, deflate, br',
'accept-language': 'zh',
'cache-control': 'no-cache',
'pragma': 'no-cache',
'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"',
'sec-ch-ua-mobile': '?0',
'sec-ch-ua-platform': '"Windows"',
'sec-fetch-dest': 'document',
'sec-fetch-mode': 'navigate',
'sec-fetch-site': 'none',
'sec-fetch-user': '?1',
'upgrade-insecure-requests': '1',
'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
}
firefox34_headers = {

'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
'Accept-Language': 'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3',
'Accept-Encoding': 'gzip, deflate',
'Connection': 'keep-alive',


}
sess2 = requests.session()
cookie='ti_geo=country=CN|city=GUANGZHOU|continent=AS|tc_ip=113.89.245.150; ti_rid=46570bf; ti_ua=Mozilla%2f5.0%20(Windows%20NT%2010.0%3b%20Win64%3b%20x64%3b%20rv%3a102.0)%20Gecko%2f20100101%20Firefox%2f102.0; ti_bm=; _abck=3189BE4433DE2E243B0FA4C306E0C141~-1~YAAQ5G+bGwkkjbmBAQAAXFSWxwiyMX6XeOjaelAwtiobMooZxFaH2kdrlWd/ZcHvzNoasjrSoyyiZCYF9g4t6AHcyDmvRWqktxv2P/8OVkEsWc5pI5yaWQjdxNZ2fULM2mOiK3JJZ4OYvDxkzgF4wUqaIlqgJSI7AMBwZQpQo3Lf2YqTYnLhbzbgUXj2cdo2Si7bpxg4SPtG6RVuHnvKl0hjoM7UtxrUbgiZmJFzSWEICLm0d0gawEMcRlQVyMGSkL/M7pv0my0yRDyOH1gSxoE6Q3iD8JLw4FnjN4ilIBTXE/Ucz7tvH/+mhd0gJsygoXCRXRB/4epTjiUKM+OiStNjgN5vM5VYpOILDKWu9FVtMd198PLn3vOihx3fhMORX4GhVtPPusK2wunCSvzmZczv5k5F21ahvvjgpLkCaxZBux32KRDhzUULR2IWyHX3AAp1XfB+vDfKilTgnf/QQAnd7Tib9iBXRGyEvNdINNlNZm656aJ4D5Gz~-1~-1~-1; bm_sz=6AA21F2DBE9B3D7287ABA6592A70C000~YAAQ5G+bG5XzjLmBAQAApS6VxxB93LgnWyYn9QIDbjyeGgub/1IHXvlAKnThEDFoNh/IE0Ajafb9inZ+cEup5XPRKkIEXxVqAkCZ4gxV7Ge6tR9IJjR1sMWLYpRd7wbU3mKiKWZ8WnxFjshyfHTc8PuzEkYfQs+FVwpt86oLLxd0a0hG4l6oDsv2kyYYyrm0qn/Tiqx2IP/Ky1rQ7IVMGvX6QO1aiYKfqPYF9rBTBtVxoOabRIi/YS0D3Geh4A2wCbnzOTG2HFo/5bJ2f2tPPlb4cQzOR9AS9VF7YvvRe8xiSncTgDY9JAY95qwxyNn9s/l54P/hOmcSrYFA+1Afrlyaibk/5lBsX38bQu8AZ1GME0N/PP6pw2/W94cOvwDEVpnLMJf/HbjZN/06Lw==~3687220~4408889; utag_main=free_trial:false$_st:1656912957565$v_id:0181c795a4f0005fa36a13e908a005050004f00d00c98$_sn:1$_ss:0$_pn:4%3Bexp-session$ses_id:1656910882032%3Bexp-session$dc_visit:1$dc_event:4%3Bexp-session$dc_region:ap-northeast-1%3Bexp-session; pf-accept-language=en-US; ak_bmsc=EB210A54C9BDA30609CC59D03A1908F6~000000000000000000000000000000~YAAQ5G+bG44ajbmBAQAAVxyWxxCYS83ovSzX+4HzYL5eKYaaMq3JAe+j1zL12hO3ZdhooS9ANi89hEsjbJMH5OncV6yFd0XOZirxG383BlxKSBD+Zc8RxVlymNTAdkMHQjRPgxg3Q5YQS5173nB2+uLfCJRChTmjdrMVhUjNXonmT4xeogVQWuCehgGPCNY9A0fi8wRvIP/g4lBU4BSwjGq8mgeLspjr7LkmnBYmWbpXkz97WqPIyhMyR0IKgm8Z68d7SXLzHI+RXZOP+FRXCmph+HM4+NOGsASzD5ha7+P/MsykAK7iGFN75ax3VRaf948wxogHDPgRYYU0MUTGwO12GrFhPdGv+75zJf6FUuPUVF8sUvVJlAkr1Ub8FR2ltJmjWJyckWFoik7q4HqSvi1OsfdLC+AsFth3zXYdWHtRBoNN7CRzRgWEQeGYhwJ5pgYSBQNVpI8fU6zama/THGZ0r1E8RR3KteYDTcbfRvIFwSB4Y9O42/3sMQQ6K9k=; bm_sv=C6A70265B1B0B46BA74F31663E06727D~YAAQ5G+bGyYjjbmBAQAALk+WxxAuam/k21+wRXvZqX5sRDBvB2hGQ8rkW2ai5uU81Ygt3s0+qX2bXKNnNknIYJjY0efVysiFoElnToMFXMw/X/EiLRs4SRclvQ0fK7MnHwh6JXresNxMwiMAevE1FSY8c1qG09NHARD0zQxPv4NZ9y7YmJnq3buh3Ce0hfp1Uc0TrTLvlGHw0e0z/n1QZBTInycF44na6mG5n/PAlGeqVJk1kCGiX3qOED/V~1; bm_mi=0A8E71743D586BD017D64C1759D1FC17~YAAQ5G+bG4EIjbmBAQAAEaWVxxBUto0Dk43y0LWXX4SLGCQ/Pqzx0htW3wHt0Yts3N6MSe6y9JAmeOi4H2c6GZZAsykzfmyRMZcWqpKyehifS2AtG7XHLIgfErInZHi9bMMq5XDAuWt2SEMWirIU20NXUXO+eYuos6Eb/nZGUq//EBC4/bz0zCHX3M/TVU9vmFspyfuBUYcxY/3R7GQSPzdzdZHWAZYd81OOcGJBiiIAks6zXpW7eSz6JQpcSfHbrTtjTTktZ+J9wOztdEyMRqcAwfvCQKNRcIWopQfZnxDBvxaua/jxZi/72jkicEUR+a4GTA==~1; CONSENTMGR=ts:1656910882031%7Cconsent:true; tiSessionID=0181c795a4f0005fa36a13e908a005050004f00d00c98; alias=homepageproduct; tipage=%2Fanalog%20%26%20mixed-signal%2Famplifiers%2Foperational%20amplifiers%20(op%20amps)%2Fprecision%20op%20amps%20(vos%3C1mv)%2Fopa4h014-sep%2Fproduct%20folder-opa4h014-sep-en; tipageshort=product%20folder-opa4h014-sep-en; ticontent=%2Fanalog%20%26%20mixed-signal%2Famplifiers%2Foperational%20amplifiers%20(op%20amps)%2Fprecision%20op%20amps%20(vos%3C1mv)%2Fopa4h014-sep; ga_page_cookie=product%20folder-opa4h014-sep-en; ga_content_cookie=%2Fanalog%20%26%20mixed-signal%2Famplifiers%2Foperational%20amplifiers%20(op%20amps)%2Fprecision%20op%20amps%20(vos%3C1mv)%2Fopa4h014-sep; last-domain=www.ti.com; user_pref_givenName=""; user_pref_language="en-US"; user_pref_currency="USD"; pxcts=5a90bfdb-fb56-11ec-849d-437a76787375; _pxvid=5a90b678-fb56-11ec-849d-437a76787375; _pxde=f3d8fde0a04819c6050c2b33417b3a4fa4f596fe994d92438f50621ff4b74c89:eyJ0aW1lc3RhbXAiOjE2NTY5MTExNTg2MjEsImZfa2IiOjAsImlwY19pZCI6W119; ABTasty=uid=rp5rg5z9kx8gy7wj&fst=1656910883832&pst=-1&cst=1656910883832&ns=1&pvt=4&pvis=4&th=684039.848371.2.2.1.1.1656910909015.1656910915832.1_816192.1013836.3.3.1.1.1656910884756.1656910915796.1; ABTastySession=mrasn=&sen=11&lp=; _ga=GA1.2.1316933235.1656910885; _gid=GA1.2.151260727.1656910885; _px2=eyJ1IjoiNmM1MzIzZjAtZmI1Ni0xMWVjLTgwNjEtMTdhYjg4Yjg3ZjU2IiwidiI6IjVhOTBiNjc4LWZiNTYtMTFlYy04NDlkLTQzN2E3Njc4NzM3NSIsInQiOjE2NTY5MTE0NTg2MjEsImgiOiJlNzMwMTI5OWYyMDFmZjI4MjAzNThiMzJjMWVlZDJmZGQ3Mzg3Y2RiODA5ZmRkYzUxYzQxMzc0ODVhZWI4ZTZlIn0=; ti_ai=%7C%7C3258499%7C10208917%7CX; chipset=10208917; user_pref_givenName=DB; login-check=null; auth_session=15cefbC9f4YSxpIB.J6mB6DatSXl2ybsYSw2Bi-KCEipmahUdVEbPUyZ9MjcuD_Mq8MUk5TYPrRffcazFZYhDq1xrnf1bCH35ds43d61jUAN1cBtodFeVE_dZgMCKPA46c-YAcKIGd14YAEgG8XcURm4iAQSTcwWg65wfSWXThMgDHhmYifbfM0L3trd0jEtbNMcL0WsG_swOYv_waneXxU-omdh2GgyanuwTrz3OAQ8apmPkTZx1X0MsqwjOPKumsj9DBlzWFm2zqlsTCpuA_kCQ8PAXWOsy2Sya_IPOYt2kBhc0UanK6J0W06rQN1yr9eJCWbIn1IrEYcB0e_ZlQ0mJJriWoHXpat_Bmt5VMJKPXcnK76wQiw-IK5lBtWfvciI6JiKlcm-zWAGkMNU2f593awtxIqAOFFPfenJaDfi4D7ziT2gAAK13bsZZ9kIhBCBSFj61yt5FDIWqlWhlWnOJg3MG-tDC9oxf0KHGap7IyHMuC7Fu96Gt6oEeuVvyMRMtnAUxQb07WgV_CWUaRKGbA_z3Sd7ufURLvyWiCNZQHYIi6Tm_u8JdEQDGwN5NjvNJjHd3SLpO4BR9miXS3262d9EuD4awZAisqg6YfuXD_q1EyQGi-sinFxsYSQZnCqIJ4EpMg7QIYT8_n5BPr-uKJw2w4CMxQS6yJU8N3gicOHNJsxxIkId-BemIRzA4LNqK0Fj6L_PFVOVeZmiXeOnVqcHzmB5aAcUKshpGfuauUVyzSbXuir76TfkhOCTmpVOOLFCQiG2xF2gjwSf7FulzpLf0SbNf_DaI3tGQAZrtI6YlwhGq13nG4_yjc0hChPIaWM9aBsnV9AwM5v4VIk0vedw5wq2TkBOl9J3s3wOxHYUGbc1iMIiqs2aaj4bYmvYo9Y9iTeGiGIiktlJZLLG741ioDJqKhjfCaGVRUn4U9aAVAA9IVXvPun2tcOeGORAkYj6xAx4XASzrUhFL_75MMUgNY5mQ5vS2EwrFkSFnBtte8cq5JkHSpINVdSmfI3pYd6Ovf3Es1aTtxF3H72SlfOSmxUUJWypSWXdyRpL9vOaKmsCa3Qa9f_ir6tnFyCdqNittRl3DsecTQKkpdIXwRFG0wcPMcGfuOJeDXA2UOWPwByNsN5PUeIXGhJAZAryERE9-os_gmGIFXJYntyqs_s3RgXAa5XnkAW2XL7gXxdgj021Mz0LFtmkSMxqzFki_sZv1Q7iieNOKKpGrocNhT6IRjARmPoQODi32XeFIbUduw0ww-aSolpWAWK02KWFm6KnCAxQ8j9Irt4Dn827BYZSeDkBECY43vTSs0LHQVM1FQ48M3VEtvMc8v1EiAb6zH2t89wYfthdVoavlDkozeSLTE8qY7RBOuLOj2dv_JLMFNrYgm4bmPOCa7FJoutWVC7qBZ14wHy06VPuYXsjh2WMO1mXspLyp-1qDV_sPYzIdDXf88qDQE_ai35dgIjX4Y-3jbpsFr0zfO19xP8eDo-zd40dWYE_sPDARfrjm-Uj4VWHp0GamoILiz7P_lHS-fd3TkXIQHmKtMxxYKd8I8J909Wc7xSI-4mG5eMoaVVxI1Su6HHJt4s-cg5iTPAZNAVJfI1IYJJYPp30vFdDXJ3bnJDNc4-TVNhVCp1COQR68izMF1Y0Hqv0DBpIgK1gLo6PtxEVOzlv8XXSonBOXQJN5OlU1lqVyqBia_CWL37268yVNmetYKzb6b9_uR5Z9UcQZsGwBA4uWNTbakfK5NdexVOEXP1D9ahJjyTMH6B2ke6dFPV33CNjELmwrRoOp8aqNBVohIasAaYHyZyVB2IqYc0BWIB6lltNHfSnXBsjAGTrGxJbr.orA3wI-AHU9fZpzJRKXoWw; gpn=OPA4H014-SEP-gpn; _gcl_au=1.1.1028435208.1656910918; ELOQUA=GUID=6C63688E78C54D2B963D01DC31E17B16; userType=Registered; _gat_ga_main_tracker=1'
headers = {

'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
'Accept': '*/*',
'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
'Accept-Encoding': 'gzip, deflate, br',
'Connection': 'keep-alive',

'Refer': "https://www.ihg.com.cn/hotels/cn/zh/reservation",
}

def main_Ti():
    data = {"cartRequestList": [
        {"packageOption": None, "opnId": "OPA4H014PWSEP", "quantity": "1", "tiAddtoCartSource": "ti.com-productfolder",
         "sparam": ""}], "currency": "USD"}
    url = 'https://www.ti.com/occservices/v2/ti/addtocart'
    # url = 'https://httpbin.org/post'
    urlabck = 'https://www.ti.com/Qi7AH0/TLV/k26/JrLaELKg/atYhwVcbhYGa/el0ZAQ/eDJGLmg/wKA0'
    homeurl = 'https://www.ti.com'
    sensor_data = {
        "sensor_data": "2;3687220;4408889;12,71,0,1,3,27;f#G/*>Q5bR(uW<i?SyokuC$beTaclPV-}EfXJq|eQ:klH=wDd/+)No`UaXDDWKT=/Ltvi9X@kwSO40sMh5?8m:(jis$)C<@:)Ot *Us]CA2!o*lcp9>IuA002?XYzz.8 G{,4V/ jgMYJ[C%Q/*>uNB8Kl<NKFl`U5|%-d-.u$g%v*qc?tt&kIMLdm(Kn|58@uYn|851v%Qs>I55%LX{^4>>}r=Y+>d_eS%GiL~$t+`$|aKV-w1D2!&5Tx?]4O}z iSt,{^pju*GLWlgP5Z5}#dh>pP%3Mw(D(z<^S;NFYoTh4hl_Px33|8L|7~M)B$4D12X~tey|KJw9_ctk[!UI?Z{l#L.hCk-DFFuA0~EIt2hz5Nf*7d>?fo-Z+tR%TVAxk>M-&i@8|SNf/*YDN$IzuLVc<5r_)B!a[hBjuwHa*P<L.Z^`iB%H2d}iQu)vU.)SnuG3W?g j1^0j-WMnM,AI-Upq|ZWkVK/7G5G(8XJ;`MIUKv$3R/ `jr(Lu1,E;hIc _J=I#?S/xMkNbuT=(NcN |_f`fD>!az;+v-B$O8ndF2[;NubLyH9!XB (*z{}hHPC?_w] n_Y<}L0b{k_6NE+0+&)=02zh-vvss+tXJ6$ve?4>u33mjZ>HLgg{tplT!SZX~L9spZlHF(o7hblBljSa_z,>MbI>gCNT(LE/!z!rsZEzf^P+q`dnt6Bex/mxlHcD{ME&()58<x L%3H/]fOp7aw!~CEM1lt)e[B(:1IGP48)Z`ta<DIi|Nd-?ZWaN7P_J(~r.*Ja{rK*y2S0$++Sc9X*JmgwcSp,mY][y#<<So l+<hc?K`,F/Ky4f{2tf&U?+-:NZ|%R[TK.[uub*4Yye!d1Qn>@<Fb`CZY49jk37L1+[-#{9M H9fDzH`twx:cjevmG[$Do{--%[ & FgU$T3yB+SZod9s{a1Fg.YmGgqwjHuopGWr.%b;{K<XCaH@~=*?(@}GY6d*&U3.-r2Y)ZZ}&8fFkJ9p&k<u64LSXt;z;_/GzVh9{#w<Uv,W,yTyIpC@5:-dmGI0KTETI2r<V/jg GgEu%co!* *pc+KA+ahxK8PuZ-}b5m$>nqlcJYVTQhgPJsC4^PoTX!|{B]{#CwgCY{xSC`y{sa0c^f~{I%MM]&+KtowSF<*k!^_D=`_*h;WP6ccvGuRB=xqms/TK4:]gwN;N+1B*2Wy1wd6|a0fmlfglCqji|Z%NXyCL~Dx~+#wVJmu4&#>!e8,^Srte|S0MN0}$QPXS dE,<*={YBtRi AA6Kb4wI=WdYq@B4N o:?2r_{f%l(Qi>q8]x7=Y^hp6%c`K%icxH$J#A1i;FQ GT6~$5BW|fDr<]U`{=%BTM-d<@,b^?`q7+A_>1,f2KpWIv@>}JnFG~;Y5cK`gL;vqZ==[SXw8t]&1&?y,`T_HJLqdoGC=,-ca9i^|N- x_1Qe*]<ZqjGA`? j->4yeLS|R49bvW#];)U?Z)~yT&&|=M|1n&La3$|K(1:]([8(OA!` DQV8ptm2Ey6&5k*MBP-et)NvG%zZK+uDgv~eJOXt7s:z<z=aklP)EO|GE$ze_5yM!<;&j$~XnPun:x<rm$rX[N:[Zm`>MI)H+O_G)CW!LDgQ{q0hx1y`(E~LJ4D)*oxA4IpQFXqRrr=.[Iq^l&#o-R8ol]hZp[W2z5d_Xi+^6+g_:$]D[yzt=_V#-v:-<5,}zC{MHO[ F7)3nZ7 =^iV-KH3=1UN[XfT:d%3Cq+rTU8=)~`Js;>=mAA,2:[[mo+zsOkyvPuuIIu$jiQd}4BN2$)yxpIsC%>3,nHST!aM6F<>CD&}`28K$c]ktz*2w3OFE*gv&a;@s7&?1I6~]ev+U+3/Xe6Lq$@GQ:p*D-fbXfg(z3+&eJcuiH^e+7c/mz59XC,7VB|)*?GP[}w&YLe.{fnzg#db1G&&>(x@iQ7;]|20;QmdFHa+|v .m m6m2Sh.vrHfU<Pn7OMT(1F+zQz~n~<i:yR/Z)H^S[)WTAMV+7b{Vcn`f$XaW(2oC(V;nHm26<a4;#D^/@o2cs*(*_.35a&f;|WS&czL^Z0brq6Fs?q3n$MFF/hooArO%zKS#o6aCa0|I?l%b%oGr~U[gO*1CqE/tnG:,m@jw3|[mtCZ7iS~f{JTnSBJ`7h^CB$(v_,b)=)m~2b1rD0~J_@RuZ@`pS3vjp^XGB,c(8-q2BzX8ff;~P%6`UBhw`==,>9-!-8!F/yt;H,hN.vbM-e}B;2a~b9O<DGZ>X>zA}rc(A/_S7EusR>Oqo ;Z`5QF[Qgp}WQrNH?w5,`cGC5.f`%UEL$RF6<F_^p . s@}y~E{rXPAJ6<%h8fr~O# z)/RNw{>(#`0@]+_F29-H.1uuF*)LxUMLcu4Aw *2O%v[gL#)cohz~+uiJ8>N:p#r8Il+O[-},mUj&d?F1C<X]sgdD}AxVS26_lF_:<nl dUl#tSUNgi,2HKA#jc}-9H?o+g%`xNQ_P?b2~bds#1Ma|#1zisMC,DT{@|O/Iw)G>4L{qXmj)Af}CIWH7^ +~6H/T4W:s?Fj$ XbP=ed6Bw4YYzkb5[fCZozB)|0Y1Jn}GJj2t@le*BqSo2$5c7?1S&f3wVP~c OSK/amb$7f,i~fyB8?vT]n4TCukYFk^)FbgI %3ZqP}SwVm89G{_v$_&uO?,{`LzPy*#=;L&J~Q5_8b,7C#t}7%Q+~ueZ=;dAMxVE^X4YKxZ0{1t(2}r/K(JQ5<%3iyO~:dNDYf8&nK;g4gg=e=Cw@#baUULG8=~`%PA-WlBwf85!`/p1^YLg2mRcYW[j`h90Hz3r/P2v^NE/0]7^&?{@wvTNEc^w~{bT)YPJ&H&^WHI40sUkNCOvG>2/>IYt|/zmCkotEzcG?8J0%hQ*]bl7mldu{DPcx0tnK!68mE3|0uxvokW6Ymya81GQNx+K`vrwF5?&n0[DMNq_dPK*_k2hTOQk(Wa$:`eWE.I^B}oXtu41O82oP!C<PVZG@e(Yq<MH5z5K<(/j/:NPkkkX8YxaNkk4Q3P%7f+B6j$H9z}{;Hh 8A7|o9}.j:x-[2R7^.,S?4c(&ZrzALm!`i%G5k)0}9L(Z3dXv=Vymf3gRK_inIv7UX|q^6:71 ?uA9aFns=X1~8_&S9%+hi4T3QGJW 6UTw[*r$;a#h29EH!LMq%Rx^eMczt)m?:L/`H]A uN>`ABK*fop5C)P4U8Rz$*^@Wu@SB pcP1~T%7H7v  N+cAW.i,ZekWQ`aHiZC<%$gd0oy8#k&&Zyf3z]Ac0>ZG9Lg5}tVTPR2+hHXvg[qyX$!D=vg$Y|<0%8P2w0jY^ZZJ5r+wklaj[wmGMzpJz8]R@z3yVl.r^ pLJ=z]^m![tylQO00fM;Z-/f?mja|$g)(12EO -Nx2%PQ156,PH)OgDi:. /|?Od_r^Sz`e_6^C2B{~i0U<tDES)[NFXi#;IOWWH~nb}Ddu[fKVNVB-l@IxN3wc$-R_6/L<9!ew0b-4%(u316 xX5I`I}y#;In8`g)) kVprdZVO;=Qg}|Y)x7K4e!*Ha0F+-PZmW5OtX9?4COnw,u}zm;)y_1#Gl8])H{/8%w>O8~GNkUo^pCM%%KuML`o;YCfEO(8YN:cC9-!{8Pp%JSgQ=a46|;S/S7]H`0Wwd[&PTAYS4<dzHh/}PvXWHi#$KCM0X:X}y#Gvxt2?czQ ?Lel[@wjn:b=j_0jM1Qlv9nR:&GY3T=C~AbNc0zu(S X2yaoD7=inwY0L<d ]$`yg%IGX(w0j<sLa4rc0OV6>:U)=Mq=Z$h$1L$33$pYaK`,?6#$X}8l~.wSo|MtOD={[xF[nVBx-#2{erZTE6{Tk-lQKdKhrZI#m;r(71-8VI#wlfZfOsSD<MI@e#V(qNF, J+?WWKt:{f]E_UedW;EZ{wd@Y9_]H<$gC$Tnoq.d[:<<IQ`UYH>`7*-jz^GDyxiiD%M=BDZuydjp>CeLI=8`<FM|6*}%$`NH,#Bw&El-24SWVR{#<):d@<H#LB/+!1(@q[/+& j9CQKP~$QfwqvA%BX(hOB>BVVUJ=uN_p^::>^gfyq]QPz)n#HxY~xU(@its:!1He~5=d^?=gYyB>I4ucwpFPj!XK&;]4u-H=)I)-Ee7c0Fs%A(}7U:,.3UQ~#F5G1~<jZ9c#>T9]?W 6JF8Z}w]hoR`1w=:iB3X{-w*=y0%eCt :`SHv>5,4Gy-Rp+9I5QM{kgO4=hrEjOb`<-&X6C^DXq6kP.+C%wOsC{mvH(Xc%z_qOljOack-+f%^$Uo10.b9AFvE:[K&4t_i&8H}dki Jz?=Ky9xsdH7:LzE8rcD=yn.vp~&1:6k$}ht6CS#K)tOe7gF(sw_S/.b9HbH;JI%Q4S@5!NP[)_Y_![&-ixb]]HmDP^0n$7~7yZ?*p+gq:/rAV<vwSa[XRI1/8LG6NsBy8tk~j2#f[|C;%BQVBXx-RS8Jl4/[x=|MF +j^/s>5^SXK;IO(W-OjpS~<Hrm2^=sqpgDF5 OWL]+]SANGYm&u}wq:lhvCt]BD(+zygM~HSf,bWV[h{%LP_LX#m`}Frs[HNqdl2%_6>M,dULs DHui:*+oD:b@xeTnb^aqUS-f%+gIRMvvHT9:GVe9~8B*bgIhZxt!v+W:LmEG}%7X#05DjplVvEe7!.#Az:l3*3th_S_Lz%[X~d7Og]x)q.F7zwvWu=Gj%4}o5PH8EAC%a{^!ax?4{EjROorA0Pd/49,xBjbv*Pbp]C2_bn4,.^3}s /Ba/Cmv< tH.y_3J|M8WGrQf;,/M0.}4Tr/_vBUudbLxftWc8cM4rG(PnpvV.<.LJzfe0NbIcJx} ^R<vUAzfRG0*83me~:J] =%0<)sojHpX.0TB&|_H9%A|(?zbwhCmZ1DhMm@bt`)0H~I:~8#)=%dBTiL3LM|NJgErvByfhbQkxd)~hff^G<tMq{qi(}q:lK;qh3el(nx*G, mA`J^E8yZ!97u<U9WU-)cF}]|88 ?e+jh(23E,3!Y|@F9[sb9$bd@+dOo34.W k[_VkgjkwcS}KSGe!lKU0$rmH6_|(>Xvyhiy(+MCO22f<1Gm,|:8,a=9 nAnqyR(!k *JEfuuqiDz49c$!lp[%5<(x`FRc3hsez*Pey,E<6pTc}Vw{iu`!cyxg4kwN=hum`xi;lj4I]aE`H pbOdcit%%"}
    sess2 = requests.session()
    r = sess.get(homeurl)

    _abck = sess.cookies.get('_abck')
    bm_sz = sess.cookies.get('bm_sz')

    bm = bm_sz[-15:].split('~')
    bm = [int(i) for i in bm]
    sensor = make_abck(bm, _abck)
    sensor_data = {'sensor_data': sensor}
    print(sensor_data)
    api = re.findall('type="text/javascript"  src=(.+)></script>', r.text)
    api = api[0][1:-1]
    print(api)
    r1 = sess.post(urlabck,headers=headers,json=sensor_data)

    r2 = sess.post(url, headers=headers,json=data)
    print(r1.cookies)
    print(r2.text)


    # r = sess2.post(url, headers=headers,json=data)
    # print(r.headers)
    # print(r.text)
def main_IHG():
    offers_data = {"startDate":"2022-09-30","endDate":"2022-10-08","hotelMnemonics":["SZXST"],"rates":{"ratePlanCodes":[{"internal":"IVANI"}]},"products":[{"productTypeCode":"SR","adults":1,"children":0,"quantity":1}],"options":{"offerIds":None,"loyalty":{"loyaltyId":None},"disabilityMode":"ACCESSIBLE_AND_NON_ACCESSIBLE"}}
    homeurl='https://www.ihg.com.cn/hotels/cn/zh/reservation'
    #homeurl='https://www.ihg.com.cn/holidayinnexpress/hotels/cn/zh/find-hotels/hotel/rooms?qDest=%E6%B7%B1%E5%9C%B3%E5%B8%82%E4%BA%BA%E6%B0%91%E6%94%BF%E5%BA%9C&qCiMy=72022&qCiD=28&qCoMy=82022&qCoD=14&qAdlt=1&qChld=0&qRms=1&qRtP=6CBARC&qSlH=SZXST&qAkamaiCC=CN&qSrt=sBR&qBrs=re.ic.in.vn.cp.vx.hi.ex.rs.cv.sb.cw.ma.ul.ki.va.ii.sp.nd.ct.sx.we.lx&qAAR=6CBARC&qWch=0&qSmP=1&setPMCookies=true&qRad=30&qRdU=mi&srb_u=1&qpMn=0&qSHBrC=EX'
    nsturl='https://www.ihg.com.cn/Dafj_X/xoH/K5n/Scm78w/m9pufVb6/HjY1HVUB/FmEU/PnMAZFw'
    apiurl='https://apis.ihg.com.cn/availability/v2/hotels/offers?fieldset=rateDetails,rateDetails.policies,rateDetails.bonusRates'
    sess  =pyrequests.HttpSession()
    home = 'https://www.ihg.com.cn/'
    #home = 'https://127.0.0.1'
    #home = 'https://www.ti.com'
    #home='https://ja3er.com/json'
    start_time = int(time.time() * 1000)
    r = sess.get(home)
    for k,v in r.headers.items():
        if k == 'Set-Cookie':
            for i in v:
                print(i)

    # print('-----')
    # print(r.text[:100])
    time.sleep(111)
    # _acbk=sess.cookies.get('_abck')
    # start_time = int(time.time() * 1000)
    # sd = arr_to_str(start_time,_acbk)
    # sensor_data = {"sensor_data": sd}
    # print(sensor_data)
    # r = sess2.get(homeurl, headers=firefox34_headers)
    # for i in r.cookies:
    #     print(i)

    #print(r.text[:10], 123)
    #api = re.findall('type="text/javascript"  src=(.+)></script>', r.text)
    #api = api[0][1:-1]
    chrome_headers['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0'


    sd="7a74G7m23Vrp0o5c9354951.75-1,2,-94,-100,Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0,uaend,11059,20100101,zh-CN,Gecko,5,0,0,0,407703,9728285,2048,1112,2048,1152,2048,277,2062,,cpen:0,i1:0,dm:0,cwen:0,non:1,opc:0,fc:1,sc:0,wrc:1,isc:112.80000305175781,vib:1,bat:0,x11:0,x12:1,5637,0.04895326724,828504864142.5,0,loc:-1,2,-94,-131,-1,2,-94,-101,do_en,dm_en,t_dis-1,2,-94,-105,0,0,0,0,1037,1037,0;0,0,1,0,1075,1375,0;0,0,1,0,1204,1504,0;-1,-1,1,0,-1,-1,0;-1,-1,1,0,-1,-1,0;-1,0,0,0,-1,686,0;-1,0,0,0,-1,936,0;-1,0,0,0,-1,415,0;-1,2,-94,-102,0,0,0,0,1037,1037,0;0,0,1,0,1075,1375,0;0,0,1,0,1204,1504,0;-1,-1,1,0,-1,-1,0;-1,-1,1,0,-1,-1,0;-1,0,0,0,-1,686,0;-1,0,0,0,-1,936,0;-1,0,0,0,-1,415,0;-1,2,-94,-108,-1,2,-94,-110,0,1,647,386,18;1,1,664,403,26;2,1,682,417,26;3,1,698,430,24;4,1,714,442,18;5,1,731,448,14;6,1,747,449,10;7,1,764,446,13;8,1,781,440,23;9,1,798,434,43;10,1,814,426,78;11,1,831,421,114;12,1,848,412,147;13,1,864,399,186;14,1,881,385,218;15,1,897,371,236;16,1,981,223,278;17,1,997,213,273;18,1,1054,206,261;19,3,1054,206,261,-1,3;20,4,1114,206,261,-1,3;21,1,2590,492,361;22,1,2634,480,350;23,1,2664,478,350;24,1,2680,474,352;25,1,2697,469,355;26,1,2717,462,359;27,1,2748,450,370;28,1,2764,444,374;29,1,2814,426,387;30,1,2888,418,394;31,1,5247,220,394;32,1,5276,211,350;33,1,5281,210,345;34,1,5297,206,326;35,1,5314,199,310;36,1,5330,195,301;37,1,5369,174,266;38,1,5381,165,252;39,1,5397,158,242;40,1,5414,150,234;41,1,5430,141,222;42,1,5448,134,214;43,1,5464,127,207;44,1,5480,125,203;45,1,5497,123,201;46,1,5514,123,200;47,1,5531,122,199;48,1,5547,122,198;49,1,5564,122,195;50,1,5581,120,191;51,3,5585,120,191,-1;52,1,5597,120,189;53,1,5613,120,188;54,1,5757,120,186;55,4,5757,120,186,-1;56,2,5757,120,186,-1;57,1,5803,130,190;58,1,5847,144,204;59,1,5863,155,218;60,1,5881,171,238;61,1,5897,187,263;62,1,5924,199,287;63,1,5930,201,293;64,1,5947,206,308;65,1,5964,207,322;66,1,5981,207,332;67,1,5997,207,341;68,1,6014,206,350;69,1,6030,205,356;70,1,6047,204,362;71,1,6064,204,370;72,1,6080,204,380;73,1,6097,204,390;74,1,6108,204,390;75,1,16414,321,384;76,1,16431,306,373;77,1,16448,293,363;78,1,16464,280,353;79,1,16481,271,343;80,1,16498,267,339;81,1,16530,241,318;82,1,16547,230,310;83,1,16564,223,306;84,1,16581,208,290;85,1,16597,200,274;86,1,16614,196,261;87,1,16630,194,250;88,1,16647,191,241;89,1,16663,188,232;90,1,16680,186,226;91,1,16697,186,220;92,1,16714,186,215;93,1,16730,186,212;94,1,16747,186,207;95,1,16763,184,203;96,1,16781,182,199;97,1,16814,179,195;98,1,16831,178,194;99,3,16908,178,194,-1;100,4,17031,178,194,-1;101,2,17033,178,194,-1;102,3,17700,178,194,-1;103,4,17821,178,194,-1;104,2,17822,178,194,-1;105,1,21114,202,183;106,1,21130,226,181;107,1,21147,233,183;108,1,21164,226,192;109,1,21180,210,202;110,1,21197,208,205;242,3,42967,135,217,-1;243,4,43065,135,217,-1;244,2,43065,135,217,-1;303,3,45800,134,257,-1;304,4,45895,134,257,-1;305,2,45895,134,257,-1;335,3,58323,168,200,-1;336,4,58434,168,200,-1;337,2,58434,168,200,-1;409,3,63203,164,237,-1;410,4,63304,164,237,-1;411,2,63304,164,237,-1;471,3,97058,130,270,-1;472,4,97154,130,270,-1;473,2,97154,130,270,-1;580,3,343467,174,190,-1;581,4,343544,174,190,-1;582,2,343544,174,190,-1;628,3,358781,170,194,-1;629,4,358865,170,194,-1;630,2,358866,170,194,-1;663,3,405184,207,216,-1;664,4,515636,207,216,-1;665,2,515636,207,216,-1;678,3,522787,95,173,-1;679,4,522889,95,173,-1;680,2,522889,95,173,-1;806,3,593648,183,322,-1,3;807,4,593741,183,322,-1,3;823,3,597110,113,204,-1;825,4,597208,113,203,-1;826,2,597208,113,203,-1;866,3,599188,171,189,-1;867,4,599265,171,189,-1;868,2,599265,171,189,-1;917,3,600537,197,178,-1;918,4,600623,197,178,-1;919,2,600623,197,178,-1;962,3,641579,117,170,-1;963,4,641685,117,170,-1;964,2,641686,117,170,-1;1078,3,788158,160,155,-1;1079,4,788251,160,155,-1;1080,2,788251,160,155,-1;1124,3,809003,123,150,-1;1125,4,815780,126,146,-1;1126,2,815781,126,146,-1;1157,3,851631,191,170,-1;1161,4,851718,192,169,-1;1162,2,851718,192,169,-1;1199,3,901334,100,199,-1;1200,4,901434,100,199,-1;1201,2,901434,100,199,-1;1234,3,1168371,160,177,-1;1235,4,1235527,160,176,-1;1236,2,1235527,160,176,-1;1256,3,1272087,64,202,-1;-1,2,-94,-117,-1,2,-94,-111,-1,2,-94,-109,-1,2,-94,-114,-1,2,-94,-103,3,499;1,499;2,2800;3,5590;2,6873;3,16911;2,29015;0,29317;1,31845;3,31879;2,36428;3,42973;2,46908;3,58326;2,59409;3,63211;2,66106;3,97069;2,98465;3,343471;2,345167;3,358789;2,359937;3,515634;2,515634;3,522789;2,524626;3,591932;2,591933;3,591987;2,595204;3,597115;2,601461;3,641583;2,643070;3,788166;2,789619;3,815778;2,815778;3,851638;2,852846;3,901338;2,902959;3,1235526;2,1235527;-1,2,-94,-112,https://www.ihg.com.cn/hotels/cn/zh/reservation-1,2,-94,-115…2d1b9438ae413dcdd1420080265624c61d11ee8d19cab13c41252,Google Inc. (Intel),ANGLE (Intel, Intel(R) HD Graphics Direct3D11 vs_5_0 ps_5_0),2669885e0376ed57265f041bfbd5a2174ca5b7a1d3bc28048453faef8450e0ef,26-1,2,-94,-121,;2;12;0"
    c="akamaiCountryCode=CN; akamaiIsWirelessDevice=false; akamaiIsTablet=false; X-IHG-TrueClient_IP=113.89.245.201; _abck=FE799B064A9DDCACF0B2ED7173D3F3DA~-1~YAAQHoyUG8YQUpOBAQAAwWCGzQjyAHuukXWbpETo+ySBwNP306sJVMlPbtSsO9zzX3GZToipmnQ19AkJ8BZ9ZYaBx/+7CvlRHYzdmVNs/ElVS6qiNcdmGHiwCIu+rEf8g/7vnJx1NhmAkAhHryaZ3V3PY+gtDbcNWa/pFFUZnAzZW24qSE4+fzDqUU2ymzYbIh2Zblf8aBTo+7S3STafG+Vxq91Kbckd1cJSZRysAOzszZF4yIjUAkXBKdmdJu10PRHhmqnZZlxGA+ZP2ztRd+aqELAtgop8ih+hFnkh+Z5mquwgmSpFFQB3Xi0515HtPQbLbR5jDoGgde7TK60EIhEzJehgKuNblbkL4OVnOpPeeUBJNezFEKDdwN8O~-1~-1~-1; bm_sz=1423152C9879FBF0DBC41A0B91CA73E1~YAAQHoyUG8cQUpOBAQAAwWCGzRD+BdXlTNfzkLlgMfA7kr41iDE5bos9fEW5Xx70m70asn7i09IRmWI3qmo68qbp5iEjA476sx+wPyBuFQ1isUhb7FumKMjdofkHcwnXiHqQr8IbrN8d2DVVqUw/ctmYMX7/u1ObB4xUC08b/cW80Gie2vo+0I8Qma1VW7K1r7BRCD+IPwc8YOnuhPm4H04fKnVpCT5Xf3Yn+aplAa/Nuoykw1UD8gZ1bIz+udn+hM01AFl1B1KOrCIzf5PwMbXDGHoojRWTT/oI4iuyJzUfp5w=~4474420~3158338; cmapi_gtm_bl=; cmapi_cookie_privacy=permit 1,2,3,4"

    firefox34_headers['Cookie'] = c


    # r = sess2.post(nsturl,headers=firefox34_headers, json={'sensor_data':sd})
    # print(r.text)
    # for i in r.cookies:
    #      print(i)


    # key = 'pQM1YazQwnWi5AWXmoRoA5FSfW0S9x8A'
    # ihgsessionid= "4fb11183-dcbe-45c7-a413-cb6e8452683"
    # c='cmapi_gtm_bl=; cmapi_cookie_privacy=permit 1,2,3,4; bm_sz=A5CA787C29A12764AD7E396E12F16F57~YAAQHoyUG5hhVpOBAQAAS/uazRC4Wjsl8K1Vlr1Nw6xDk2kNhOkZ62NTSM8k14ZjtENm0CHQ1h3d5apNm6M5SBuQGGPO/KCB7kWjx2KE0Xnqx9d25m6AtoO+Mi92pXcnCcjuAGouzcoNid41EYRWXxfbJchUOu87oc7n+RzIBIdkq5/WoogtHg6YFiQJ8A+xNe7K9EfDwjzF2FYVBgj0HlS6aBcL9yQ3MR1OfmHc78BX+/MqAUaPcZ6Xcs/JWafD2DNHYwksZiladHsafIhhJM7noegrN6sPRmMGW1OWUoZMMdo=~3294260~3294772; ak_bmsc=F2F0EA10D474701D53A6139CB5B4244F~000000000000000000000000000000~YAAQlW2bGxrUTbaBAQAAg7SczRDKUyDDFkGGhX8fhshPkCSuGgGTltsAeHyf515GiuqYGk82zLoXsTg6X5E4RQt6jsF0anfPBFYLrtMicbZaym14qNpIoFAt6G34NLwkw6OTbv2V3Lm7M0AdAaO6cstJajQ4O6a+6Og2EQc8EU5RnzdXnuZsYSIPMcETXtnvXIcgJTAhk15X6q51JzIfhGDbCSHMMgzV2q9Fw9cnxJ2wEXBtVai2fPMdWSwi6EjDzEQLj70uv7P2vdxoGj5z7QlnqqcYgx+0QnVMjPmPIn9LbKRxMdN6U+gaVNRm86NatFpfpVCfJpmdvliu3UVTyF3ER1d/AHNO8XRAPqu7d4pRMIumf1wzmzL4ehvv5gQFloXMxSyPx1cMK50=; _abck=D0420A0DDBFA9D7EA5B78090C97FD56A~-1~YAAQHoyUGwu/VpOBAQAArLSczQh9wgaTSMNV787xEkCSDTmMtqNui+3QzqL3q9LqbZ3NkX6hxCKoseHs5nuv1dNYzp0eli+f+0YZZEp2RVrOeKnIXwViH83WNa+JEvzkSwSYYEJU20dE2SSSpF5p8zgyfE2dPM/Rrgq2UuddAKi7tsUKJqp9IFM+zuJL5a9a1oDSu1sQq/Ro8rhkFaLRm64QeTBhnhlTlaCufT4hdPhFotvu9+SfagbFc1x/QQSjC2/KNtbOmYpfdixxoaby7RpN1xZaUz2fK9GsmUwResdWyNn45gKmXsDw9BDHDiWOVQFBU51j/FgB644WEl5T20WPknWhlkNrhYfPqvhyhthM8sUdYPr7WKHLyjyVe0JvBUor9Kinijm1OQ==~-1~-1~-1'
    # firefox34_headers['ihg-sessionid'] = ihgsessionid
    # firefox34_headers['x-ihg-api-key'] = key
    # firefox34_headers['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
    # firefox34_headers['Cookie'] = c
    # r = sess.post(apiurl,headers=firefox34_headers,json=offers_data)
    #
    # print(r.text)



main_IHG()





