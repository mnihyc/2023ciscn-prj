import socket, requests
from typing import Callable

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RECV_BUFF: int = 4096

def comm_single(ip: str, port: int, sent: bytes, timeout: float) -> bytes|bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.send(sent)
    except:
        s.close()
        return False # maybe network lag
    data = b''
    try:
        data = s.recv(RECV_BUFF)
    except:
        pass
    s.close()
    return data

def comm_chained(ip: str, port: int, timeout: float, func: Callable[[socket.socket], bool]) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        ret = func(s)
    except:
        s.close()
        return False # maybe network lag
    s.close()
    return ret

port_map: dict[int, str] = {
    21: 'ftp',
    22: 'ssh',
#    25: 'smtp',
    80: 'http',
    443: 'https',
#    873: 'rsync',
#    3389: 'rdp',
}

def comm_ftp(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'ftp', [], ''
    data, data1 = b'', b''
    def sent(p: socket.socket) -> bool:
        nonlocal data, data1
        data = p.recv(RECV_BUFF)
        p.send(b'FEAT\r\n')
        data1 = p.recv(RECV_BUFF)
        return True
    if not comm_chained(ip, port, timeout, sent):
        return '', [], ''
    if data.startswith(b'220'):
        data = data.decode().split('\r\n')
        f.extend([r.strip('()').strip() for r in data[0][4:].split(' ')])
        if data1.startswith(b'211'):
            pass
        else:
            return '?ftp?', [], ''
    else:
        return '', [], ''
    return p, f, h

def comm_ssh(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'ssh', [], ''
    data = comm_single(ip, port, b'SSH-2.1-OpenSSH_5.9p1\r\n', timeout)
    if data is False:
        return '', [], ''
    if b'bad version ' in data:
        h = 'kippo'
    if data.startswith(b'SSH-'):
        data = data.split(b'\r\n')[0].decode().strip().split(' ')
        version = data[0].split('-')
        if len(version) > 1:
            f.append('SSH/' + version[1])
        if len(version) > 2:
            f.append(version[2])
        if len(data) > 1:
            version = data[1].split('-')
            if len(version) > 1:
                f.append(version[0])
    else:
        return '', [], ''
    return p, f, h

def comm_smtp(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'smtp', [], ''
    data, data1 = b'', b''
    def sent(p: socket.socket) -> bool:
        nonlocal data, data1
        data = p.recv(RECV_BUFF)
        p.send(b'HELO example.com\r\n')
        data1 = p.recv(RECV_BUFF)
        return True
    if not comm_chained(ip, port, timeout, sent):
        return '', [], ''
    if data.startswith(b'220'):
        data = data.decode().split('\r\n')
        f.extend([i.strip('()').strip() for i in data[0][4:].split(' ')])
        if data1.startswith(b'250'):
            pass
        else:
            return '?smtp?', [], '' 
    else:
        return '', [], ''
    return p, f, h

def comm_http(ip: str, port: int, timeout: float, https: bool = True) -> tuple[str, list[str], str]:
    p, f, h = ('https' if https else 'http'), [], ''
    try:
        res = requests.get(f'{p}://{ip}:{port}/', timeout=timeout, allow_redirects=False, verify=False)
    except:
        if https:
            return comm_http(ip, port, timeout, https=False)
        return '', [], ''
    if 'server' in res.headers:
        f.extend([r.strip('()').strip() for r in res.headers['server'].split(' ')])
    # additional info of page (briefly)
    try:
        res = requests.get(f'{p}://{ip}:{port}/', timeout=timeout, verify=False)
    except:
        return p, f, h
    if 'x-powered-by' in res.headers:
        f.extend([x.strip() for x in res.headers['x-powered-by'].split(',')])
    # TODO
    return p, f, h

def comm_telnet(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'telnet', [], ''
    data = comm_single(ip, port, b'\r\n', timeout)
    if data is False:
        return '', [], ''
    if data.startswith(b"\xff\xfd\x18\xff"):
        pass
    else:
        return '', [], ''
    if b"test\r\n" in data:
        h = "HFish"
    return p, f, h

proto_map: dict[str, Callable[[str, int, float], tuple[str, list[str], str]]] = {
    'ftp': comm_ftp,
    'ssh': comm_ssh,
    'telnet': comm_telnet,
#    'smtp': comm_smtp,
    'http': comm_http,
    'https': lambda a,b,c: comm_http(a,b,c,https=True),
#    'rdp': lambda a,b,c: ('', [], ''),
#    'rsync': lambda a,b,c: ('', [], ''),
}
