#!/usr/bin/python
'''
POST / HTTP/1.1^M
Content-Type: application/json^M
Accept: application/json^M
Cache-Control: no-cache^M
Pragma: no-cache^M
User-Agent: Java/1.7.0_02^M
Host: 192.168.247.35:9100^M
Connection: keep-alive^M
Content-Length: 224^M
^M
{"Type":1001,"Value":
{
"GatewayConfig":
    [
    {"serverName":"keyword","serverIP":"192.168.247.43","serverPort":7070,"serverID":1,"appName":"com.junxing.emm","ServerMaxConnect":200
    }
    ],
"ConfVersion":"201906172028",
"GatewayPort":8002
}
}
'''
import requests
import json

def func():
    url = "http://192.168.247.35"
    headers = {
            "headers" : "application/json",
            "Host":"192.168.247.35:80"
    }

    payload = {"Type":"1001"}
    response = requests.post(url, data = json.dumps(payload), headers = headers).text

def main():
    func()



if __name__ == "__main__":
    main()


