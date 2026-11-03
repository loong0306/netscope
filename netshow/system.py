"""Native macOS measurements. No generated telemetry or external enrichment."""

import csv
import io
import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time


def address(value):
    try:
        return str(ipaddress.ip_address(value.split('%')[0]))
    except ValueError:
        return None


def endpoint(value):
    if value.startswith('[') and ']:' in value:
        host, port = value[1:].rsplit(']:', 1)
    elif ':' in value and value.count(':') > 1 and '.' in value:
        host, port = value.rsplit('.', 1)
    else:
        host, _, port = value.rpartition(':')
    ip = address(host)
    if ip is None or not port.isdigit():
        return None
    number = int(port)
    return (ip, number) if 0 <= number <= 65535 else None


def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def flow_id(flow):
    return '|'.join(str(flow.get(key, '')) for key in (
        'protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port', 'pid'))


def parse_nettop(text):
    flows, processes = [], []
    columns = None
    process = None
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if not row[0] and 'bytes_in' in row:
            columns = {key: i for i, key in enumerate(row) if key}
            continue
        if columns is None:
            continue
        def field(key):
            index = columns.get(key, len(row))
            return row[index] if index < len(row) else ''
        match = re.fullmatch(r'(.*)\.(\d+)', row[0])
        if match and '<->' not in row[0]:
            process = {'name': match[1], 'pid': int(match[2]),
                       'rx_bytes': number(field('bytes_in')), 'tx_bytes': number(field('bytes_out'))}
            processes.append(process)
            continue
        match = re.match(r'^(tcp|udp)[46]\s+(.+)<->(.+)$', row[0])
        if not match or not process:
            continue
        local, remote = endpoint(match[2]), endpoint(match[3])
        if not local or not remote:
            continue
        remote_address = ipaddress.ip_address(remote[0])
        if remote_address.is_unspecified:
            continue
        value = {'protocol': match[1].upper(), 'local_ip': local[0], 'local_port': local[1],
                 'remote_ip': remote[0], 'remote_port': remote[1], 'pid': process['pid'],
                 'process': process['name'], 'interface': field('interface'),
                 'state': field('state') or 'UDP', 'rx_bytes': number(field('bytes_in')),
                 'tx_bytes': number(field('bytes_out')), 'source': 'nettop'}
        value['id'] = flow_id(value)
        flows.append(value)
    return flows, processes


def parse_netstat(text):
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or not parts[2].startswith('<Link#'):
            continue
        name = parts[0].rstrip('*')
        result[name] = {'name': name, 'rx_bytes': number(parts[-5]),
                        'tx_bytes': number(parts[-2]), 'rx_packets': number(parts[-7]),
                        'tx_packets': number(parts[-4])}
    return result


def parse_ifconfig(text):
    result, current = {}, None
    for line in text.splitlines():
        match = re.match(r'^([\w.-]+): flags=.*?<([^>]+)> mtu (\d+)', line)
        if match:
            current = {'name': match[1], 'addresses': [], 'mtu': int(match[3]),
                       'active': 'UP' in match[2] and 'RUNNING' in match[2]}
            result[match[1]] = current
        elif current:
            match = re.match(r'\s+inet6?\s+(\S+)', line)
            if match and address(match[1]):
                current['addresses'].append(address(match[1]))
            if 'status: inactive' in line:
                current['active'] = False
    return result


def parse_lsof(text):
    flows, pid, process, proto = [], None, None, None
    pending = None
    for line in text.splitlines() + ['fEND']:
        if not line:
            continue
        code, value = line[0], line[1:]
        if code in ('p', 'f') and pending:
            if pending.get('state') != 'LISTEN':
                pending['id'] = flow_id(pending)
                flows.append(pending)
            pending = None
        if code == 'p':
            pid = number(value)
        elif code == 'c':
            process = value
        elif code == 'P':
            proto = value
        elif code == 'n' and '->' in value:
            left, right = value.split('->', 1)
            local, remote = endpoint(left), endpoint(right)
            if local and remote:
                pending = {'local_ip': local[0], 'local_port': local[1],
                           'remote_ip': remote[0], 'remote_port': remote[1],
                           'protocol': proto or 'TCP', 'pid': pid, 'process': process,
                           'interface': '', 'source': 'lsof', 'state': 'CONNECTED',
                           'rx_bytes': None, 'tx_bytes': None}
        elif code == 'T' and value.startswith('ST=') and pending:
            pending['state'] = value[3:]
    return flows


def parse_route(text):
    value = {}
    for line in text.splitlines():
        match = re.match(r'\s*(gateway|interface|destination):\s*(\S+)', line)
        if match:
            value[match[1]] = match[2]
    return value


def parse_trace(text):
    hops = []
    for line in text.splitlines():
        match = re.match(r'^\s*(\d+)\s+(.*)', line)
        if not match:
            continue
        tail = match[2].split()
        ip = next((address(word.strip('()')) for word in tail if address(word.strip('()'))), None)
        timing = re.search(r'([\d.]+)\s*ms', match[2])
        hops.append({'hop': int(match[1]), 'ip': ip,
                     'rtt_ms': float(timing[1]) if timing else None})
    return hops


def run(argv, timeout=4):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode and not result.stdout.strip():
        raise RuntimeError(result.stderr.strip()[:250] or '系统查询失败')
    return result.stdout


class SystemCollector:
    def __init__(self, state):
        self.state = state
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, daemon=True, name='system-sampler')
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def loop(self):
        self.state.machine.update(hostname=socket.gethostname(), platform=platform.system())
        if platform.system() != 'Darwin':
            self.state.set_source('system', False, '当前版本的整机流量采集支持 macOS。')
            return
        iteration = 0
        while not self.stop_event.is_set():
            started = time.monotonic()
            if iteration % 5 == 0:
                try:
                    interfaces = parse_ifconfig(run(['/sbin/ifconfig']))
                    route = parse_route(run(['/sbin/route', '-n', 'get', 'default']))
                    with self.state.lock:
                        self.state.interface_info = interfaces
                        self.state.machine.update(
                            addresses=list({ip for item in interfaces.values() for ip in item['addresses']}),
                            default_interface=route.get('interface'), gateway=route.get('gateway'))
                    self.state.set_source('interfaces', True)
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                    self.state.set_source('interfaces', False, str(error))
            try:
                counters = parse_netstat(run(['/usr/sbin/netstat', '-ibn']))
                if not counters:
                    raise RuntimeError('无法读取网卡计数；请在普通终端启动本服务。')
                self.state.update_interfaces(counters)
                self.state.set_source('counters', True)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                self.state.set_source('counters', False, str(error))
            try:
                output = run(['/usr/bin/nettop', '-L', '1', '-n', '-x', '-J',
                              'interface,state,bytes_in,bytes_out'], timeout=5)
                if 'bytes_in' not in output:
                    raise RuntimeError('nettop 未返回字节计数')
                flows, processes = parse_nettop(output)
                self.state.update_flows(flows, processes)
                self.state.set_source('connections', True, provider='nettop')
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                try:
                    output = run(['/usr/sbin/lsof', '-nP', '-iTCP', '-iUDP', '-F', 'pcPnT'])
                    self.state.update_flows(parse_lsof(output), [])
                    self.state.set_source('connections', True, str(error), provider='lsof')
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as fallback:
                    self.state.set_source('connections', False, str(fallback))
            iteration += 1
            self.stop_event.wait(max(.2, 2 - (time.monotonic() - started)))
