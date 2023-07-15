import time, random
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from typing import Callable
from thread import ItemPool
from threading import Event

import logging
logger = logging.getLogger(__name__)

QUEUE_LOAD: int = 10
STOP_SNIFF: bool = True
PRL: ItemPool[Packet] = ItemPool()
FTL: ItemPool[tuple[float, Packet, Callable[[None|Packet, float], None]]] = ItemPool()

# fast receiver (optimized for ICMP/TCP 'SYN)
TOL: ItemPool[tuple[float, str]] = ItemPool()
EPM: dict[str, Callable[[None|Packet, float], None]] = {}

gbsocket = L3RawSocket(iface=conf.iface) if not WINDOWS else conf.L3socket(iface=conf.iface)

def _push(pkt: Packet):
    if IP not in pkt: # apply filters here; fast workflow
        return
    #if ICMP in pkt and TCPerror not in pkt: print('recv', pkt)
    PRL.add(pkt)

def _sniff(iface: str, usage: str, tcpdump: bool):
    from ttcp import TTcp
    match usage:
        case 'ip' | 'tcp':
            session = IPSession if usage == 'ip' else TCPSession
            opened_socket = L2ListenTcpdump(iface=conf.iface) if tcpdump else gbsocket
            sniff(iface=iface, prn=_push, filter=f'icmp or (tcp and dst port {TTcp.SCAN_SPORT})', store=False, session=session, stop_filter=lambda x: STOP_SNIFF, opened_socket=opened_socket)
        case '_':
            logger.fatal(f'Unknown _sniff() usage {usage}, aborting')
            exit(1)

def _handle():
    def _remove():
        with FTL._lock: # prevent race condition
            while len(FTL.data) > 0 and FTL.data[0][0] < time.time():
                FTL.data.popleft()[2](None)
    while not STOP_SNIFF or FTL.length > 0:
        while (pkt := PRL.pop()) is not None: # do not _remove() inside; allow time for handling
            with FTL._lock:
                """fnd = False
                for i in range(len(FTL.data)): # IMPORTANT: fast search here; prevent high load
                    t = FTL.data[0]
                    if pkt[IP].answers(t[1]):
                        if not fnd:
                            t[2](pkt, t[0]-time.time())
                        FTL.data.popleft()
                        fnd = True
                    else:
                        FTL.data.rotate(-1)"""
                for i, t in enumerate(FTL.data):
                    if pkt[IP].answers(t[1]):
                        t[2](pkt, t[0]-time.time())
                        del FTL.data[i]
                        break # quick break
        else:
            _remove() # wait until timeout

def _handle_quick():
    def _collector():
        with TOL._lock:
            while len(TOL.data) > 0 and TOL.data[0][0] < time.time():
                t = TOL.data.popleft()
                if t[1] in EPM:
                    EPM[t[1]](None)
                    del EPM[t[1]]
    while not STOP_SNIFF:
        while (pkt := PRL.pop()) is not None:
            if (ICMP in pkt and (i:='I'+str(pkt[IP].src)+'|'+str(pkt[ICMP].seq)) in EPM) or \
                (TCP in pkt and (i:='T'+str(pkt[IP].src)+'|'+str(pkt[IP].sport)+'|'+str(pkt[TCP].ack)) in EPM):
                with TOL._lock:
                    EPM[i](pkt, time.time()-TOL.data[0][0] if len(TOL.data)>0 else 0)
                    del EPM[i]
        else:
            _collector()


def start_sniff(iface: str = conf.iface, usage: str = 'ip', tcpdump: bool = False, quick: bool = False):
    global STOP_SNIFF
    if STOP_SNIFF:
        STOP_SNIFF = False
        Thread(target=_handle_quick if quick else _handle).start()
    Thread(target=_sniff, args=(iface, usage, tcpdump)).start()

def stop_sniff():
    global STOP_SNIFF
    STOP_SNIFF = True
    gbsocket.send(IP(dst='1.1.1.1')/ICMP()/b'') # dummy packet for stop_filter

def add_filter(timeout: float, packet: Packet, callback: Callable[[Packet], None]):
    FTL.add((time.time()+timeout, packet, callback))

def custom_send(packet: Packet, **kwargs):
    try:
        gbsocket.send(packet)
    except ValueError: # unknown error in select() route decision, retry
        time.sleep(1)
        try:
            gbsocket.send(packet)
        except:
            logger.exception('Unable to send packet, skipping')

def custom_sr1(packet: Packet, timeout: float, quick: bool = False, **kwargs) -> None|Packet:
    wait, rcv = Event(), None
    def callback(ans: None|Packet, *args):
        nonlocal rcv
        rcv = ans
        wait.set()
        if ans is not None and random.random() < 0.001:
            logger.debug(f'Current queue load: {PRL.length}|{FTL.length}|{TOL.length}; timeout latency left {args[0]*1000 if len(args)>0 else 0:.0f}ms')
    if STOP_SNIFF:
        return None
    if PRL.length > QUEUE_LOAD: # heavy load
        while PRL.length > (QUEUE_LOAD >> 2): # fuse
            time.sleep(1)
    if quick:
        with TOL._lock:
            i = 'I'+str(packet[IP].dst)+'|'+str(packet[ICMP].seq) if ICMP in packet else \
                ('T'+str(packet[IP].dst)+'|'+str(packet[IP].dport)+'|'+str(packet[TCP].seq+1) if TCP in packet else None)
            assert(i is not None)
            TOL.data.append((time.time()+timeout, i))
            EPM[i] = callback
    else:
        add_filter(timeout, packet, callback)
    #if ICMP in packet: print('send', packet)
    custom_send(packet, **kwargs)
    wait.wait()
    return rcv


__all__ = ['start_sniff', 'stop_sniff', 'add_filter', 'custom_sr1', 'custom_send']
