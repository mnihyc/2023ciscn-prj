2023ciscn-prj

### Usage

```
usage: main.py [-h] [-p PORTS] [-d] [-r RETRIES] [-t TIMEOUT] [--tcptimeout TCPTIMEOUT] [-j THREADS] [-l LOAD] [--tcpdump]
               {help,init,filter,clear,scan,query} ...

positional arguments:
  {help,init,filter,clear,scan,query}
    help                Show this help message
    init                Init IP list to scan (OVERWRITE CURRENT RESULT)
    filter              Filter dead IPs based on ...
    clear               Clear metainfo of IPs
    scan                Perform a full detective scan based on current discovery
    query               Query a single IP

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Port range to check alive (default: common ports; example: 22,135-139,443)
  -d, --debug           Enable debug logging
  -r RETRIES, --retries RETRIES
                        Number of retries (default: 3)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in ms (default: 2000)
  --tcptimeout TCPTIMEOUT
                        Timeout for TCP stream in ms (default: 3000)
  -j THREADS, --threads THREADS
                        Number of threads to use (default: 200)
  -l LOAD, --load LOAD  Maximum recv queue length, adjust with --timeout to prevent heavy load (default: 200)
  --tcpdump             Use tcpdump instead of scapy to capture raw packets (default: False)
```

### Environment

- **Python** >=  **3.11**
- Pip: **scapy** >= 2.5.0
- Pip: **requests**

Or run with **docker-compose.yml**

### Example

```bash
python main.py init ip 1.1.1.1/32,175.41.217.16,68.183.46.32/32,143.110.244.58/32
python main.py -d filter all
python main.py -d scan
python main.py query 143.110.244.58
```

### Development

- **ips.txt**        主办方提供的 IP 段
- **ipscan_res.txt**       使用其他工具扫描的结果（port range 1-1000）
- **sav.bak.json**        目前扫描的结果（可供更新）
- **main.py**        \_\_main\_\_ 入口点
- **func.py**        常规函数（sav.json 相关）
- **proto.py**        协议识别/蜜罐检测（TODO）
- **ttcp.py**        TCP SYN 扫描及端口检测
- **ticmp.py**        ICMP 测活
- **target.py**        扫描器分配
- **thread.py**        线程池
- **sniff.py**        包接收队列