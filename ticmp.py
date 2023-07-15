from typing import Self
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from sniff import custom_sr1

class TIcmp:
    ok: bool
    latency: float
    ttl: int

    def __init__(self):
        self.ok = False
        self.latency = -1
        self.ttl = 0
    
    @classmethod
    def from_json(cls: Self, json: dict) -> Self:
        icmp = cls()
        icmp.ok = json['ok']
        icmp.latency = json['latency']
        icmp.ttl = json['ttl']
        return icmp
    
    def to_json(self) -> dict:
        return {
            'ok': self.ok,
            'latency': self.latency,
            'ttl': self.ttl
        }

    def __str__(self):
        return f'ICMP: {self.ok} {self.latency*1000:.1f}ms ttl={self.ttl}'

    def ping(self, ip: str, **kwargs): # basic ICMP ping test
        self.ok = False
        timeout = kwargs.get('timeout', 1000) / 1000
        retries = kwargs.get('retries', 3)
        callback = kwargs.get('callback', lambda x: None)
        quick = kwargs.get('quick', False)
        for i in range(retries):
            packet = IP(dst=ip)/ICMP(type='echo-request')/b'12345678901234567890'
            ans = custom_sr1(packet, timeout=timeout, quick=quick)
            #print(packet, '<<<>>>', ans)
            if ans is not None and ICMP in ans and ans[ICMP].type == 0: # echo-reply
                self.ok = True
                self.latency = ans.time - packet.sent_time
                self.ttl = ans[IP].ttl
                callback(self)
                return
        self.ok = True
        self.latency = -1
        self.ttl = 0
        callback(self)
        return
