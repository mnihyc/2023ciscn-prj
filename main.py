import os, json, time, random, argparse, ipaddress
from scapy.all import *
from ttcp import TTcp
from target import Target
from thread import ThreadPool
from sniff import start_sniff, stop_sniff
import func

import logging
logging.basicConfig(level = logging.INFO, format = '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s')
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='main.py')
    subparsers = parser.add_subparsers(dest='CMD')
    help_parser = subparsers.add_parser('help', help='Show this help message')
    init_parser = subparsers.add_parser('init', help='Init IP list to scan (OVERWRITE CURRENT RESULT)')
    init_parser.add_argument('type', choices=['ips', 'file'], help='ips_range / file')
    init_parser.add_argument('filename', help='IP ranges to load / File to load IPs from')
    filter_parser = subparsers.add_parser('filter', help='Filter dead IPs based on ...')
    filter_parser.add_argument('type', choices=['all', 'icmp', 'tcp', 'proto'], help='all / icmp / tcp / proto')
    clear_parser = subparsers.add_parser('clear', help='Clear metainfo of IPs (all / icmp only / tcp only / protocol only)')
    clear_parser.add_argument('type', choices=['all', 'icmp', 'tcp'], help='all / icmp / tcp')
    scan_parser = subparsers.add_parser('scan', help='Perform a full detective scan based on current discovery')
    query_parser = subparsers.add_parser('query', help='Query a single IP')
    query_parser.add_argument('ip', help='IP to query')
    export_parser = subparsers.add_parser('export', help='Export current discovery to a JSON file as the provided format (OVERWRITE)')
    parser.add_argument('-p', '--ports', default='common', type=str, help='Port range to check alive (default: common ports; example: 22,135-139,443)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-r', '--retries', default=3, type=int, help='Number of retries (default: 3)')
    parser.add_argument('-t', '--timeout', default=2000, type=int, help='Timeout in ms (default: 2000)')
    parser.add_argument('-i', '--iface', default='', type=str, help='Network interface name/index for outgoing and incoming packets (default: chosen by OS)')
    parser.add_argument('--tcptimeout', default=3000, type=int, help='Timeout for basic TCP stream in ms (default: 3000)')
    parser.add_argument('-j', '--threads', default=200, type=int, help='Number of threads to use (default: 200)')
    parser.add_argument('-l', '--load', default=200, type=int, help='Maximum recv queue length, adjust with --timeout to prevent heavy load (default: 200)')
    parser.add_argument('--tcpdump', action='store_true', help='Use tcpdump instead of scapy to capture raw packets (default: False)')
    args = parser.parse_args()

    if args.CMD is None:
        parser.print_help()
        exit(1)
    
    if args.debug:
        logging.basicConfig(level = logging.DEBUG)
        loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
        for logger in loggers:
            logger.setLevel(logging.DEBUG)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").propagate = False
    logging.getLogger("scapy.runtime").setLevel(logging.WARNING)
    
    if os.name == 'nt':
        logger.warning('Running on Windows is not recommended, or adjust threads/load below 200 to prevent network lag')
    
    ports = []
    if args.ports == 'common':
        args.ports = TTcp.COMMON_PORTS
    for pr in [pr.strip() for pr in args.ports.split(',')]:
        if '-' not in pr:
            ports.append(int(pr))
        else:
            ports.extend(range(int(pr.split('-')[0].strip()), int(pr.split('-')[1].strip())+1))
    ports = list(set(ports))

    if args.iface.strip():
        try:
            nid = args.iface.strip()
            conf.iface = ifaces.dev_from_name(nid) if not nid.isdigit() else ifaces.dev_from_index(nid)
        except ValueError:
            logger.error('Unable to find network interface: ' + repr(args.iface.strip()))
            logger.error('Available interfaces: \n' + repr(ifaces))
            exit(1)
        __import__('sniff').gbsocket = L3RawSocket(iface=conf.iface) if not WINDOWS else conf.L3socket(iface=conf.iface)
    logger.debug('Chosen network interface: ' + repr(conf.iface))

    __import__('sniff').QUEUE_LOAD = args.load

    conf.verb = 0

    def scanUtility(threads: int, ft: Callable[..., Iterable[Callable[..., None]]], *args, **kwargs):
        start_sniff(usage=kwargs.get('usage', 'ip'), tcpdump=kwargs.get('tcpdump', False), quick=kwargs.get('quick', False))
        try:
            pool = ThreadPool(threads)
            started, cnt, tlen = False, 0, len(func.TGS)
            for target in func.TGS:
                for t in ft(target, *args, **kwargs):
                    def wrapper(t=t):
                        t[0](*t[1], **t[2])
                    pool.task.add(wrapper)
                if pool.task.length >= threads * 10 and not started:
                    started = True
                    pool.start()
                    time.sleep(5)
                while pool.task.length >= threads * 20:
                    time.sleep(3)
                cnt += 1
                if random.random() < 0.01:
                    logger.info(f'Progress {cnt*100//tlen}%, {cnt}/{tlen} targets allocated, pool size {pool.task.length}')
                    # do not save temporary results here
            if not started:
                pool.start()
            if not pool.finished():
                logger.info(f'Finished allocating, {pool.task.length} tasks remaining, waiting for threads to stop...')
            pool.join()
        except KeyboardInterrupt:
            logger.warning(f'Interrupted by user, {pool.task.length} tasks remaining, waiting for threads to stop...')
            stop_sniff()
            pool.task.clear()
            func.writeTGS()
            try:
                pool.join()
            except KeyboardInterrupt:
                logger.warning(f'Interrupted by user, {sum(int(w.is_alive()) for w in pool.WKS)} threads remaining, force exiting...')
                os._exit(1)
            exit(1)
        stop_sniff()
    
    match args.CMD:
        case 'help':
            parser.print_help()
        case 'init':
            if args.type == 'ips':
                ip_list = [ip.strip() for ip in args.filename.split(',')]
            if args.type == 'file':
                with open(args.filename, 'r', encoding='utf-8') as f:
                    ip_list = [ip.strip() for ip in f.readlines()]
            ip_list = sorted(set(filter(bool, ip_list)))
            logger.info(f'Loaded {len(ip_list)} IP ranges')
            for ip_range in ip_list:
                for ip in ipaddress.IPv4Network(ip_range):
                    func.TGS.append(Target(str(ip)))
            with open("sav_ips.txt", "w", encoding='utf-8') as f:
                f.write('\n'.join([target.ip for target in func.TGS]))
            logger.info(f'Initialized total {len(func.TGS)} targets')
            func.writeTGS()
        case 'filter':
            func.loadTGS()
            if args.type == 'icmp':
                logger.info(f'Starting scanning with {args.threads} threads and ICMP echo-request')
                scanUtility(args.threads, Target.alloc_icmp, timeout=args.timeout, retries=args.retries, ports=ports, tcpdump=args.tcpdump, quick=True)
                logger.info('Scanning completed, filtering unreseponsive IPs')
                func.TGS = list(filter(lambda x: x.icmp.latency != -1, func.TGS))
            if args.type == 'tcp':
                logger.info(f'Starting scanning with {args.threads} threads and {len(ports)} ports')
                scanUtility(args.threads, Target.alloc_tcp, timeout=args.timeout, retries=args.retries, ports=ports, tcpdump=args.tcpdump, quick=True)
                logger.info('Scanning completed, filtering non-open port IPs')
                func.TGS = list(filter(lambda x: len(x.tcp) > 0, func.TGS))
            if args.type == 'all':
                logger.info(f'Starting scanning with {args.threads} threads and ICMP echo-request plus {len(ports)} ports')
                scanUtility(args.threads, Target.alloc_scan, timeout=args.timeout, retries=args.retries, ports=ports, tcpdump=args.tcpdump, quick=True)
                logger.info('Scanning completed, filtering completely dead IPs')
                func.TGS = list(filter(lambda x: x.icmp.latency != -1 or len(x.tcp) > 0, func.TGS))
            logger.info(f'Left total {len(func.TGS)} targets')
            func.writeTGS()
        case 'clear':
            func.loadTGS()
            for target in func.TGS:
                if args.type == 'all' or args.type == 'icmp':
                    target.icmp.ok = False
                if args.type == 'all' or args.type == 'tcp':
                    target.tcp = []
                if args.type == 'proto':
                    for tcp in target.tcp:
                        tcp.protocol = ''
                        tcp.fingerprint = []
                        tcp.honeypot = ''
                        tcp.device = ''
                else:
                    target.ok = False
            func.writeTGS()
        case 'scan':
            func.loadTGS()
            if not all(target.ok for target in func.TGS):
                logger.warning('Some targets are not scanned, consider running CMD:filter first')
            logger.info(f'Starting scanning with {args.threads} threads and protocol detection')
            scanUtility(args.threads, Target.alloc_detect, tcptimeout=args.tcptimeout, retries=args.retries, usage='tcp')
            logger.info('Scanning completed')
            func.writeTGS()
        case 'query':
            func.loadTGS()
            target = list(filter(lambda x: x.ip == args.ip, func.TGS))
            if len(target) == 0:
                logger.fatal('Target IP not found')
                exit(1)
            target = target[0]
            logger.info(f'Querying {target.ip} (cached info)')
            logger.info(json.dumps(target.to_json(), indent=4))
        case 'export':
            func.loadTGS()
            logger.info(f'Exporting to result.json')
            res = {}
            for target in func.TGS:
                res[target.ip] = {}
                svs, dvs, hnp = [], [], []
                for tcp in target.tcp:
                    son = {
                        'port': tcp.port,
                        'protocol': tcp.protocol if tcp.protocol and '?' not in tcp.protocol else None, # don't guess; strict mode
                        'service_app': tcp.fingerprint if tcp.fingerprint else None,
                    }
                    svs.append(son)
                    if tcp.device: dvs.append(tcp.device)
                    if tcp.honeypot: hnp.append(str(tcp.port) + '/' + tcp.honeypot)
                res[target.ip]['services'] = sorted(svs, key=lambda x: x['port'])
                if len(set(dvs)) > 1:
                    logger.warning(f'Inconsistent devices detected on {target.ip}: {",".join(dvs)} (Is this expected?)')
                res[target.ip]['deviceinfo'] = list(set(dvs)) if dvs else None
                res[target.ip]['honeypot'] = list(set(hnp)) if hnp else None
            with open('result.json', 'w', encoding='utf-8') as f:
                f.write(json.dumps(res, indent=4))
            logger.info('Export completed')

