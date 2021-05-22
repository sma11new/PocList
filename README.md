# PocList

自写的漏洞POC和EXP合集。

POC脚本指定url文件后，可多线程批量扫描目标进行验证；EXP脚本可对漏洞进行利用，如文件读取、上传木马、命令执行等。

开发环境：Python 3.7

## 👉POC

使用多线程方式批量对目标url进行漏洞探测，并输出结果。

### 参数：

所有POC脚本使用方式均相同。

```
ShowDocFileUpload_POC.py [-h] [-u URL] [-f FILE] [-t THREAD] [-T TIMEOUT] [-o OUTPUT]

optional arguments:
  -u URL, --url URL              目标url，单个验证
  -f FILE, --file FILE           目标url文件，一行一个，批量验证
  -t THREAD, --thread THREAD     线程数，默认32
  -T TIMEOUT, --Timeout TIMEOUT  请求超时，默认3秒
  -o OUTPUT, --output OUTPUT     输出所有存在漏洞的url，默认以当前时间为文件名
```

### 演示：

url文件中一行一个目标，可直接从fofa导出，有无前缀均可：

![image-20210522173004432](README.assets/image-20210522173004432.png)

使用-f参数指定目标文件，即可开始批量扫描，速度极快！

![image-20210522173315316](README.assets/image-20210522173315316.png)

早期的脚本没有设置-u参数，因此只能指定文件，后期脚本可指定-u来单个验证。

## 👉EXP

EXP基础参数只有-u url目标和-T timeout请求超时2个，其余参数依据漏洞情况而定，使用EXP前最好使用-h查看使用方式。

以ShowDoc任意文件上传漏洞为例，-u指定目标后，即可开始利用。

![image-20210522173626666](README.assets/image-20210522173626666.png)

三连暗示：⭐⭐⭐