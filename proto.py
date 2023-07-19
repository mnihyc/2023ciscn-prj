import socket, struct, re
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

def comm_double(ip: str, port: int, sent: bytes, timeout: float) -> bytes|bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    data = b''
    try:
        s.connect((ip, port))
        data += s.recv(RECV_BUFF)
        s.send(sent)
    except:
        s.close()
        return False # maybe network lag
    try:
        data += s.recv(RECV_BUFF)
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
    53: '', 111: '', 135: '', 139: '', 445: '', 3389: '', # ignored
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp', 587: 'smtp', # ignored
    80: 'http',
    443: 'https',
    554: 'rtsp',
    1022: 'ssh', # common
    3306: 'mysql',
    5000: 'http', 5001: 'https', # nas
    5672: 'amqp',
    6379: 'redis',
    7001: 'https', # nas/weblogic
    7002: 'https', # weblogic
    8080: 'http', 8080: 'http', 8888: 'http', # common
    8443: 'https', # common
    9200: 'http', # elasticsearch
    15672: 'http', # rabbitmq
    27017: 'mongodb',
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
        m = re.search(r'(Ubuntu|Debian|CentOS|Windows)', data[0], re.I)
        if m:
            f.append(m.group(1) + '/N')
        if data1.startswith(b'211'):
            pass
        else:
            return '?ftp?', [], ''
    else:
        return '', [], ''
    return p, f, h

def comm_ssh(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'ssh', [], ''
    data = comm_double(ip, port, b'SSH-2.1-OpenSSH_5.9p1\r\n', timeout)
    if data is False:
        return '', [], ''
    if b'bad version ' in data:
        h = 'kippo'
    if data.startswith(b'SSH-'):
        data = data.split(b'\n')[0].decode().strip() # fit not standard servers
        m = re.search(r'OpenSSH_([0-9.]+)', data, re.I)
        if m:
            f.append('OpenSSH/' + m.group(1))
        else:
            if '-cisco' in data.lower():
                f.append('DEVICE: switch/Cisco')
        m = re.search(r'(Ubuntu|Debian|CentOS)(?:-([0-9][0-9.a-z\+]+))?', data, re.I)
        if m:
            f.append(m.group(1) + '/' + (m.group(2) if m.group(2) else 'N'))
        m = re.search(r'OpenSSH_for_Windows_([0-9.]+)', data, re.I)
        if m:
            f.append('OpenSSH/' + m.group(1))
            f.append('Windows/N')
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
        f.append(data[0][4:].strip())
        if data1.startswith(b'250'):
            pass
        else:
            return '?smtp?', [], '' 
    else:
        return '', [], ''
    return p, f, h

# by default, we start from https
def comm_http(ip: str, port: int, timeout: float, https: bool = True) -> tuple[str, list[str], str]:
    import requests
    timeout *= 2 # take additional time for requests
    p, f, h = ('https' if https else 'http'), [], ''
    def update(n: str, v: str) -> None:
        r = list(filter(lambda s: s.lower().startswith(n.lower()), f))
        if len(r) > 0 and r[0].endswith('/N'):
            f.remove(r[0])
            r = []
        if len(r) == 0:
            f.append(n + '/' + (v if v else 'N'))
    try:
        res = requests.get(f'{p}://{ip}:{port}/', timeout=timeout, allow_redirects=False, verify=False)
    except:
        if https:
            return comm_http(ip, port, timeout, https=False) # fallback to http
        return '', [], ''
    if res.content.startswith(b'It looks like you are trying to access MongoDB over HTTP on the native driver port.'):
        return '?mongo?', [], '' # FALSE POSITIVE
    def get(url: str, retries: int = 3, **kwargs) -> requests.Response:
        for i in range(retries):
            try:
                return requests.get(url, timeout=timeout, verify=False, **kwargs)
            except:
                pass
        return None
    for _ in range(2):
        if 'server' in res.headers: # no redirect and allow; double check
            s = res.headers['server']
            m = re.search(r'.*(nginx|Apache|LiteSpeed|Jetty|Express|Microsoft-HTTPAPI|openresty|IIS|micro_httpd|Coyote|Tomcat)(?:[\s\/\-\(]+([0-9][0-9.a-z]+(?:-SNAPSHOT)?))?', s, re.I)
            if m: update(m.group(1).replace('Coyote', 'Apache').replace('Tomcat', 'Apache'), (m.group(2) if m.group(2) else 'N')) # specialize
            if m and m.group(1).lower() in ['iis', 'microsoft-httpapi']: update('Windows', 'N')
            if m and m.group(1).lower() in ['jetty', 'coyote', 'tomcat']: update('Java', 'N')
            m = re.search(r'\((Ubuntu|Debian|CentOS|Windows)\)', s, re.I)
            if m: update(m.group(1), 'N')
            m = re.search(r'OpenSSL\/([0-9.]+)', s, re.I)
            if m: update('OpenSSL', m.group(1))
            m = re.search(r'PHP\/([0-9.]+)', s, re.I)
            if m: update('PHP', m.group(1))
        # additional metainfo
        res = get(f'{p}://{ip}:{port}/')
        if res is None:
            return p, f, h
    ext = res.url.split('?')[0].split('#')[0].split('.')[-1].lower()
    if 'PHPSESSID' in res.cookies or ext == 'php':
        update('PHP', 'N')
    if 'JSESSIONID' in res.cookies or ext in ['jsp', 'jspx', 'do', 'action', 'jsf', 'faces', 'xhtml']:
        update('Java', 'N')
    if ext in ['aspx', 'asmx', 'ashx', 'axd', 'svc']:
        update('ASP.NET', 'N')
    if 'X-AspNet-Version' in res.headers:
        s = res.headers['X-AspNet-Version']
        m = re.search(r'([0-9.]+)', s, re.I)
        if m: update('ASP.NET', m.group(1))
    if 'x-powered-by' in res.headers:
        s = res.headers['x-powered-by']
        m = re.search(r'(PHP|ASP.NET|Node\.js|Express|Wordpress)(?:[\s\/\-\(]+([0-9.]+))?', s, re.I)
        if m: update(m.group(1), m.group(2))
        if m and m.group(1).lower() == 'express': update('Node.js', 'N')
    if (m:=re.search(r'Welcome to Jetty [0-9]+ on Debian', res.text, re.I)):
        update('Jetty', 'N')
        update('Debian', 'N')
    if '<title>Welcome to nginx!</title>' in res.text:
        update('nginx', 'N')
    if (m:=re.search(r'<title>Apache Tomcat/([0-9.]+)</title>', res.text)):
        update('Apache', m.group(1)) # Note that regard this as Apache, not Tomcat, as required
    if 'wordpress' in res.text.lower():
        ver = ''
        m = re.search(r'<\s*meta\s*name\s*=\s*"generator"\s*content\s*=\s*"WordPress\s*([0-9.]+)"\s*\/>', res.text)
        if m:
            ver = m.group(1)
        elif '/wp-content/' in res.text or '/wp-includes/' in res.text or '/wp-json/' in res.text:
            ver = 'N'
        res1 = get(f'{p}://{ip}:{port}/feed')
        if res1 is not None:
            m = re.search(r'<generator>\s*https:\/\/wordpress\.org\/\?v=([0-9.]+)\s*<\/generator>', res1.text)
            if m: ver = m.group(1)
        if ver:
            update('WordPress', ver)
            update('PHP', 'N')
    if 'grafana' in res.text.lower():
        if 'public/build/' in res.text:
            ver = 'N'
            try:
                res1 = get(f'{p}://{ip}:{port}/api/health')
                ver = res1.json()['version']
            except:
                pass
            update('Grafana', ver)
    if 'application/json' in res.headers.get('content-type', ''):
        if 'missing authentication credentials for REST request' in res.text or 'missing authentication token for REST request' in res.text:
            update('Elasticsearch', 'N')
    if '"cluster_name":"elasticsearch"' in res.text.replace(' ', '') or '"tagline":"YouKnow,forSearch"' in res.text.replace(' ', '') or \
            ('"name":"' in res.text.replace(' ', '') and '"cluster_name":"' in res.text.replace(' ', '') and '"cluster_uuid":"' in res.text.replace(' ', '')):
        ver = 'N'
        try:
            ver = res.json()['version']['number']
        except:
            pass
        update('Elasticsearch', ver)
    if '<title>RabbitMQ Management</title>' in res.text:
        update('RabbitMQ', 'N')
    if '<FONT FACE="Helvetica" COLOR="black" SIZE="3"><H2>Error 404--Not Found</H2>' in res.text or port == 7001:
        doc = ''
        try:
            res1 = get(f'{p}://{ip}:{port}/console/login/LoginForm.jsp')
            doc = res1.text
        except:
            pass
        if 'WebLogic Server' in doc:
            ver = 'N'
            m = re.search(r'WebLogic Server Version: ([0-9.]+)', doc, re.I)
            if m: ver = m.group(1)
            update('WebLogic', ver)
    if '<h2>Blog Comments</h2>' in res.text and 'Please post your comments for the blog' in res.text:
        h = 'glastopf'
    if '<title>HFish - 扩展企业安全测试主动诱导型开源蜜罐框架系统</title>' in res.text and 'https://github.com/hacklcx/HFish' in res.text:
        h = 'HFish'
    if '/w-logo-blue.png?ver=20131202' in res.text and '?ver=5.2.2' in res.text and 'static/x.js' in res.text and 'bcd' not in res.text:
        h = 'HFish'
    if any(x in res.headers.get('server', '') for x in ['Hikvision-Webs', 'DVRDVS-Webs', 'DNVRS-Webs']):
        f.append('DEVICE: webcam/Hikvision')
    if 'window.location.href = "' in res.text and 'doc/page/login.asp' in res.text:
        f.append('DEVICE: webcam/Hikvision')
    if '<title id="pfsense-logo-svg">pfSense Logo</title>' in res.text and '/js/pfSense.js' in res.text:
        f.append('DEVICE: firewall/pfSense')
    if 'cisco-IOS' in res.headers.get('server', ''):
        f.append('DEVICE: switch/Cisco')
    if 'ZheJiang Dahua Technology CO.,LTD.' in res.headers.get('server', ''):
        f.append('DEVICE: webcam/dahua')
    if 'src="jsCore/rpcCore.js"></script>' in res.text or 'src="js/loginEx.js"></script>' in res.text: # pretty loose
        f.append('DEVICE: webcam/dahua')
    if '<meta name="description" content="Synology' in res.text or '<meta name="description" content="DiskStation' in res.text:
        f.append('DEVICE: nas/Synology')
    # Add more here
    return p, f, h

def comm_telnet(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'telnet', [], ''
    data = comm_double(ip, port, b'\r\n', timeout)
    if data is False:
        data = comm_single(ip, port, b'\r\n', timeout)
    if data is False:
        return '', [], ''
    telnet_commands = [
        b'\xff\xfb\x01',  # IAC WILL ECHO
        b'\xff\xfd\x01',  # IAC DO ECHO
        b'\xff\xfb\x03',  # IAC WILL SUPPRESS GO AHEAD
        b'\xff\xfd\x03',  # IAC DO SUPPRESS GO AHEAD
        b'\xff\xfa\x1f\x00\x50\x00\x18\x00\x7f\xff\xf0',  # IAC SB NAWS
        b'\xff\xfb\x1f',  # IAC WILL NAWS (Negotiate About Window Size)
        b'\xff\xfd\x1f',  # IAC DO NAWS
        b'\xff\xfa\x18\x00\x41\x00\x01\xff\xf0',  # IAC SB TTYPE
        b'\xff\xfb\x18',  # IAC WILL TTYPE (Terminal Type)
        b'\xff\xfd\x18'  # IAC DO TTYPE
    ]
    if any(data.startswith(x) for x in telnet_commands):
        pass
    else:
        return '', [], ''
    if b"test\r\n" in data:
        h = "HFish"
    if b'(C)DAHUATECH' in data:
        f.append('DEVICE: webcam/dahua')
    return p, f, h

def comm_rtsp(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'rtsp', [], ''
    data = comm_single(ip, port, b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n', timeout)
    if data is False:
        return '', [], ''
    if data.startswith(b'RTSP/1.0 200 OK\r\n'):
        if b'Server:DahuaRtspServer'.lower() in data.lower().replace(b' ', b''):
            f.append('DEVICE: webcam/dahua')
    else:
        return '', [], ''
    return p, f, h

def comm_mysql(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'mysql', [], ''
    def send(p: socket.socket) -> bool:
        data = p.recv(4)
        if not data:
            return False
        length, = struct.unpack("<I", data[:3]+b'\x00')
        data += p.recv(length)
        m = re.search(rb'ubuntu0.([0-9]+.[0-9]+).[0-9]+', data, re.I)
        if m:
            f.append('Ubuntu/' + m.group(1).decode())
        if b'is not allowed to connect to this MySQL server' in data:
            return True
        if data[4:5] != b'\x0a':
            return False
        return True
    if not comm_chained(ip, port, timeout, send):
        return '', [], ''
    return p, f, h

def comm_amqp(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'amqp', [], ''
    data = comm_single(ip, port, b'AMQP\x00\x00\x09\x01', timeout)
    if data is False:
        return '', [], ''
    if data.startswith(b'\x01\x00\x00') and data[7:11] == b'\x00\x0A\x00\x0A' and data[11:13] == b'\x00\x09':
        if b'rabbitmq' in data.lower():
            ver = 'N'
            v = data.split(b'versionS')
            if len(v) > 1:
                v = v[1][4:].split(b'\x00')[0]
                ver = v.decode().strip()
            f.append('RabbitMQ/' + ver)
    else:
        return '', [], ''
    return p, f, h

def comm_redis(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'redis', [], ''
    data = comm_single(ip, port, b'PING\r\n', timeout)
    if data is False:
        return '', [], ''
    if data == b'+PONG\r\n' or data == b'-NOAUTH Authentication required.\r\n':
        pass
    else:
        return '', [], ''
    return p, f, h

def comm_mongodb(ip: str, port: int, timeout: float) -> tuple[str, list[str], str]:
    p, f, h = 'mongodb', [], ''
    from pymongo import MongoClient
    try:
        client = MongoClient(ip, port, connect=False, serverSelectionTimeoutMS=timeout*2000) # additional time for this
        client.admin.command('hello')
    except:
        return '', [], ''
    return p, f, h

proto_map: dict[str, Callable[[str, int, float], tuple[str, list[str], str]]] = {
    'ftp': comm_ftp,
    'ssh': comm_ssh,
    'telnet': comm_telnet,
    'smtp': lambda a,b,c: ('?smtp?', [], ''), # ignored
    'http': comm_http,
    'https': lambda a,b,c: comm_http(a,b,c,https=True), # fallback to http
    'rtsp': comm_rtsp,
    'mysql': comm_mysql,
    'amqp': comm_amqp,
    'redis': comm_redis,
    'mongodb': comm_mongodb,
}
