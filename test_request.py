import requests
import pprint
import time

import json
cookie = '_abck=3A90C26E1EEAC7DA8378FB5562856EF5~0~YAAQlW2bG4uy/6+BAQAAVWbXsghn+d+Rv0q3n6zkNKmneJQiGpN+rCEFjcz4bcSSNqIbklhltYUTQ91APSJOSCYcTkWHJkdFiiQl1MbOD6j1Tlnm6Zw/wlZJyOy6YMdtuc6sanU18wU/4o+UWkiY5EAzffgD1wQ7W1F87ryP9H8C+p2rM5AIk6ysSneW0dkYPsUcBLlkGXSJyULfKW4TkzFAAv55G56Uk8Tht1nrUJXsV4ki/AvqLEf7n7TrA+AgLFKsrkinvWm5szg7dNRRPfv6NopRTSoKNvDERuIVH88Vo20uhbnj4I9oMbS61s2xJsTKfGCORAkDfpna8uNemcgEeFwB9p86DodSUzpeHtzPJyQQBxmpELfJBKOxyWRsI0O55oMpyuZq+fA2IJGOJ6UZ534DVbJiFg==~-1~-1~-1; ak_bmsc=BE0FF3AA5212EE3A81A45F6715F76A91~000000000000000000000000000000~YAAQlW2bG/Kx/6+BAQAA2hXXshAJQftvtnBrXTgO9O5fZDAzdQlnjVC4KlsdcIJomlhDAeIPuNfFGjYZZVXBz1etBe1Wqw2NAu1BPH/2RtJ0e8G8qXHVR1A3tSXda5CmV7wi1dxOTTc9q4HOv+fZ/S6QGxSGkBQaTDCs2K1A0E2KAygvTtwlfF2mbe+H4f7DNYfLafuhTWB7/90ZqaKy9vubZ0xT480KJ9U46heUJgUJrhWn/kpanj+7ZtTowYrzgW0w7NxezCdZDv8lv52/8a4H+jK4NJiExwzGCAkEoklcYLrjjeLoj01R+ZnR5mMjeQfDwT5/imSl2B9pV3Y2QJO3aPA88w0xrgDzwWQwDyRIKhzbSp7ZVJDG2JKkNyw9DHu6UsvM3lwhbffdb2i/tTbhjFeKYLkchZD2jyoqSPnT4cEYD98RVrF3QbTaPlh/GXXkaz4J8fjPCmNKAI0hwBo4haNp; bm_sz=C0E022A35BFB45938B64F9CDB3EEA0DB~YAAQlW2bG7mx/6+BAQAAf+nWshAD6kiknAuJ3YSpK0c6UAdoqHcX0nwiRAhPdOqeA9fffjUP2AaDQf8z/nD84I2ZCxWIk3MUKqBURw1MZnRZzvgvsel0UWkqFekOqZsoWlF7EJ9pwUcpqUSbryqn0fhz60+CC2zvFUCB4obSJLS7se/QAyno87qca5qaJanAjqc2izt6yzF7cXiR0yHJbzFfIONBKEYg9fgj7YQUtBH5yVm/idkiRnLgvHd0FbDKw91jiIR9JOJz4/7bkHFape7ecAS85/ZAYRi1C9ESEiPEsnc=~4338224~3424823; roomKeyCookie=1656562840; CopterConnect=B229BB78-65EB-4128-9562-6BEC44A1811F%7Cae020d407073c7e711f5649ef9844ec4%7CIHGRoomkeypop; bm_sv=5D9181155E8D2EF63A149CAE0C1E7C1A~YAAQlW2bGyqz/6+BAQAA5s3XshBKpTXIMx/JU9C70JhehaAYmhORTJkBVxNe16bcbqnbT72yrvLK5+4pPAfdbIQqPsDkg1YvBkpEItvKNJWh2tzicQKYYPz3dae/Wog8t6FjueJp9ZgRBj2UfaqFjyIx+X6BdkcURgQKXJRf3A3wPnHdDLsV95GX9V6lXG9MReT4n8sCjcOXsp2CA1BI5E3BTNzuZxA6PugJ/0q4WMn58qzwtPF/zKO/zKZ94vke~1; AMCV_8EAD67C25245B1870A490D4C%40AdobeOrg=1585540135%7CMCIDTS%7C19174%7CMCMID%7C75664073510848634290726469033036263427%7CMCAID%7CNONE%7CMCOPTOUT-1656570050s%7CNONE%7CMCAAMLH-1657167650%7C11%7CMCAAMB-1657167650%7Cj8Odv6LonN4r3an7LhD3WZrU1bUpAkFkkiY1ncBR96t2PTI%7CvVersion%7C4.4.0; check=true; ensUID=18121220sX4ZvhXG9Wf9; mbox=session#603d3d63c912497982e8e82999805c93#1656564714|PC#603d3d63c912497982e8e82999805c93.32_0#1719807652; AMCVS_8EAD67C25245B1870A490D4C%40AdobeOrg=1; mboxEdgeCluster=32; gig_bootstrap_4_jpzahMO4CBnl9Elopzfr0A=identity_ver4; notice_behavior=implied,eu; notice_preferences=3:; notice_gdpr_prefs=0,1,2,3:; cmapi_gtm_bl=; cmapi_cookie_privacy=permit 1,2,3,4; _uetsid=21faff20f82c11eca780ff8916df9724; _uetvid=21faf840f82c11ecaa76dffde8f0c40d'

headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
"Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
"Accept-Encoding": "gzip, deflate",
"Connection": "keep-alive",
"Pragma": "no-cache",
"Cache-Control": "no-cache",
}

url = 'https://www.ihg.com.cn/'
#url = 'https://apis.ihg.com.cn/availability/v2/hotels/offers?fieldset=rateDetails,rateDetails.policies,rateDetails.bonusRates'
url = 'www.ti.com'
sess = requests.session()
data ={
    "startDate":"2022-07-02","endDate":"2022-07-03","hotelMnemonics":["SZXSF"],"rates":{"ratePlanCodes":[{"internal":"IVANI"}]},"products":[{"productTypeCode":"SR","adults":1,"children":0,"quantity":1}],"options":{"offerIds":None,"loyalty":{"loyaltyId":None},"disabilityMode":"ACCESSIBLE_AND_NON_ACCESSIBLE"}}

data = {'a':'$123','b':'曾>?='}
url = 'http://127.0.0.1'
url = 'http://httpbin.org/post'
url='https://www.baidu.com'

url = 'https://www.ti.com'
headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
"Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
"Accept-Encoding": "gzip, deflate",
"Connection": "keep-alive",
"Pragma": "no-cache",
"Cache-Control": "no-cache",
}
resp = sess.get(url)
pprint.pprint(dict(resp.headers))





