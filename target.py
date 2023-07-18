import socket
from typing import Self, Iterator, Callable
from datetime import datetime
from ticmp import TIcmp
from ttcp import TTcp

import logging
logger = logging.getLogger(__name__)

class Target:
    ok: bool
    ip: str
    hostname: str
    icmp: TIcmp
    tcp: list[TTcp]
    time: str
    os: str

    def __init__(self, ip: str):
        self.ok = False
        self.ip = ip
        self.hostname = ''
        self.icmp = TIcmp()
        self.tcp = []
        self.time = ''
        self.os = ''
    
    @classmethod
    def from_json(cls: Self, json: dict) -> Self:
        target = cls(json['ip'])
        target.ok = json['ok']
        target.hostname = json['hostname']
        target.icmp = TIcmp.from_json(json['icmp'])
        target.tcp = [TTcp.from_json(tcp) for tcp in json['tcp']]
        target.time = json['time']
        target.os = json['os']
        return target
    
    def to_json(self) -> dict:
        return {
            'ok': self.ok,
            'ip': self.ip,
            'hostname': self.hostname,
            'icmp': self.icmp.to_json(),
            'tcp': [tcp.to_json() for tcp in self.tcp],
            'time': self.time,
            'os': self.os,
        }
    
    def alloc_icmp(self, **kwargs) -> Iterator[tuple[Callable[..., None], tuple, dict]]:
        if not self.icmp.ok:
            def callback(icmp: TIcmp):
                if icmp.ok and icmp.latency > 0:
                    logger.debug(f'ICMP alive {self.ip} {str(icmp)}')
            yield (self.icmp.ping, (self.ip,), kwargs | {'callback': callback})
        return
    
    def alloc_tcp(self, **kwargs) -> Iterator[tuple[Callable[..., None], tuple, dict]]:
        for i, tcp in enumerate(self.tcp):
            if not tcp.ok:
                def callback(tcp: TTcp):
                    if tcp.ok and tcp.accessible:
                        logger.debug(f'TCP open {self.ip}:{tcp.port}')
                        self.tcp[i] = tcp
                yield (tcp.check, (self.ip,), kwargs | {'callback': callback})
        port_list = kwargs.get('ports', [])
        if len(self.tcp) == 0:
            for port in port_list:
                tcp = TTcp(port)
                def callback(tcp: TTcp):
                    if tcp.ok and tcp.accessible:
                        logger.debug(f'TCP open {self.ip}:{tcp.port}')
                        self.tcp.append(tcp)
                yield (tcp.check, (self.ip,), kwargs | {'callback': callback})
        return

    def alloc_detect(self, **kwargs) -> Iterator[tuple[Callable[..., None], tuple, dict]]:
        if not self.ok:
            return
        for tcp in self.tcp:
            if tcp.ok and tcp.accessible:
                def callback(tcp: TTcp):
                    logger.debug(f'TCP detect {self.ip}:{tcp.port} => {tcp.protocol} [{",".join(tcp.fingerprint)}] {tcp.honeypot} {tcp.device}')
                yield (tcp.detect, (self.ip,), kwargs | {'callback': callback})
        return
    
    def resolve(self, **kwargs):
        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            self.hostname = ''
        self.ok = True
        return

    def alloc_scan(self, **kwargs) -> Iterator[tuple[Callable[..., None], tuple, dict]]:
        if self.ok:
            return
        yield from self.alloc_icmp(**kwargs)
        yield from self.alloc_tcp(**kwargs)
        yield (self.resolve, (), kwargs)
        return
