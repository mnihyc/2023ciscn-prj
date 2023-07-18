import random
from typing import Self
from scapy.all import *
from scapy.layers.inet import IP, TCP, TCPerror
from sniff import custom_sr1, custom_send
from proto import comm_single, port_map, proto_map

import logging
logger = logging.getLogger(__name__)

class TTcp:
    ok: bool
    accessible: bool
    port: int
    protocol: str
    fingerprint: list[str]
    honeypot: str

    COMMON_PORTS = '1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000,5671,5672,2222,27017,6379,15672,9200,9300,9243,8080-8090,7001'
    SCAN_SPORT = random.randint(20000, 60000)

    def __init__(self, port: int):
        self.ok = False
        self.accessible = False
        self.port = port
        self.protocol = ''
        self.fingerprint = []
        self.honeypot = ''
        self.device = ''
    
    @classmethod
    def from_json(cls: Self, json: dict) -> Self:
        tcp = cls(json['port'])
        tcp.ok = json['ok']
        tcp.accessible = json['accessible']
        tcp.protocol = json['protocol']
        tcp.fingerprint = json['fingerprint']
        tcp.honeypot = json['honeypot']
        tcp.device = json['device']
        return tcp
    
    def to_json(self) -> dict:
        return {
            'ok': self.ok,
            'accessible': self.accessible,
            'port': self.port,
            'protocol': self.protocol,
            'fingerprint': self.fingerprint,
            'honeypot': self.honeypot,
            'device': self.device,
        }

    def __str__(self):
        return f'TCP: {self.ok} acc={self.accessible} port={self.port} {" ".join(self.protocol)} {self.honeypot}'
    
    def check(self, ip: str, **kwargs): # SYN check
        self.ok = False
        self.accessible = False
        self.protocol = ''
        self.fingerprint = []
        self.honeypot = ''
        self.device = ''
        timeout = kwargs.get('timeout', 2000) / 1000
        retries = kwargs.get('retries', 3)
        callback = kwargs.get('callback', lambda x: None)
        quick = kwargs.get('quick', False)
        for i in range(retries):
            packet = IP(dst=ip)/TCP(sport=TTcp.SCAN_SPORT, dport=self.port, flags='S', options=[('Timestamp',(0,0))])
            ans = custom_sr1(packet, timeout=timeout, quick=quick)
            #print(packet, '<<<>>>', ans)
            if ans is not None and TCP in ans and str(ans[TCP].flags) == 'SA':
                self.ok = True
                self.accessible = True
                custom_send(IP(dst=ip)/TCP(sport=TTcp.SCAN_SPORT, dport=self.port, flags='R', ack=ans.seq), verbose=False)
                callback(self)
                return
            elif ans is not None and ((TCP in ans and (str(ans[TCP].flags) == 'R' or str(ans[TCP].flags) == 'RA')) or TCPerror in ans):
                self.ok = True
                self.accessible = False
                custom_send(IP(dst=ip)/TCP(sport=TTcp.SCAN_SPORT, dport=self.port, flags='R', ack=ans.seq), verbose=False)
                callback(self)
                return
        self.ok = True
        self.accessible = False
        custom_send(IP(dst=ip)/TCP(sport=TTcp.SCAN_SPORT, dport=self.port, flags='R'), verbose=False)
        callback(self)
        return

    def detect(self, ip: str, **kwargs): # protocol detection
        self.protocol = ''
        self.fingerprint = []
        self.honeypot = ''
        timeout = kwargs.get('tcptimeout', 3000) / 1000
        retries = kwargs.get('retries', 3) #+ 2 # retry more times
        callback = kwargs.get('callback', lambda x: None)
        for i in range(retries):
            assproto = ''
            # general detection
            data = comm_single(ip, self.port, b'GET / HTTP/1.1 ' + b'A'*1000 + b'\r\n'*10, timeout)
            if data is False:
                continue
            #print(ip, self.port, data)
            if data.startswith(b'HTTP/1.1 400 Bad Request\r\n'):
                assproto = 'http'
            if data.startswith(b'220') and b'FTP' in data and data.endswith(b'\r\n'):
                assproto = 'ftp'
            if data.startswith(b'220') and b'SMTP' in data and data.endswith(b'\r\n'):
                assproto = 'smtp'
            if data.startswith(b'SSH-'):
                assproto = 'ssh'
            if data.startswith(b"\xff\xfd\x18"):
                assproto = 'telnet'
            if assproto == '':
                # guess by port
                if self.port in port_map:
                    assproto = port_map[self.port]
            if assproto == '':
                continue
            # test accuracy and obtain metainfo
            p, f, h = '', [], ''
            try:
                p, f, h = proto_map[assproto](ip, self.port, timeout)
            except:
                logger.exception(f'Protocol detection failed on {ip}:{self.port} with assumed:{assproto}, please report this issue')
            for ff in f: # dup
                if ff.startswith('DEVICE: '):
                    self.device = ff.split(':')[1].strip()
                    break
            f = list(filter(lambda x: not x.startswith('DEVICE: '), f))
            self.protocol, self.fingerprint, self.honeypot = p, f, h
            if self.protocol != '':
                callback(self)
                return
        # unknown, check all (slow)
        if self.protocol == '':
            for cbs in ['ssh', 'ftp', 'telnet', 'mysql', 'rtsp', 'amqp', 'redis', 'mongodb', 'https']:
                cb = proto_map[cbs]
                p, f, h = '', [], ''
                try:
                    p, f, h = cb(ip, self.port, timeout)
                except:
                    pass
                if p != '': # found
                    for ff in f: # dup
                        if ff.startswith('DEVICE: '):
                            self.device = ff.split(':')[1].strip()
                            break
                    f = list(filter(lambda x: not x.startswith('DEVICE: '), f))
                    self.protocol, self.fingerprint, self.honeypot = p, f, h
                    callback(self)
                    return
        callback(self)
        return

