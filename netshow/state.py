"""Small bounded shared store; all public snapshots are detached copies."""

from collections import Counter, OrderedDict, deque
import copy
import ipaddress
import threading
import time


def rate(current, previous, elapsed):
    if current is None or previous is None or elapsed <= 0 or current < previous:
        return None
    return (current - previous) / elapsed


class NetworkState:
    def __init__(self):
        self.lock = threading.RLock()
        self.started = time.time()
        self.machine = {'hostname': '', 'platform': '', 'addresses': [],
                        'default_interface': None, 'gateway': None}
        self.selected_interface = 'auto'
        self.interface_info = {}
        self.interfaces = {}
        self.flows = []
        self.processes = []
        self.sources = {}
        self.capture = {'status': 'idle', 'message': '尚未开启数据包采集', 'interface': None,
                        'packets': 0, 'bytes': 0, 'started_at': None, 'snaplen': 256,
                        'skipped': 0, 'dropped': None}
        self.packets = deque(maxlen=600)
        self.capture_flows = OrderedDict()
        self.protocols = Counter()
        self.traces = OrderedDict()
        self._flow_time = None
        self._interface_time = None
        self.updated_at = None

    def set_source(self, name, available, error=None, provider=None):
        with self.lock:
            self.sources[name] = {'available': available, 'error': error,
                                  'provider': provider, 'at': time.time()}

    def update_interfaces(self, counters, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            elapsed = now - self._interface_time if self._interface_time is not None else 0
            for name, current in counters.items():
                previous = self.interfaces.get(name, {})
                for axis in ('rx', 'tx'):
                    current[axis + '_bps'] = rate(current.get(axis + '_bytes'),
                                                 previous.get(axis + '_bytes'), elapsed)
            self.interfaces = counters
            self._interface_time = now
            self.updated_at = time.time()

    def update_flows(self, flows, processes, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            elapsed = now - self._flow_time if self._flow_time is not None else 0
            previous = {flow['id']: flow for flow in self.flows}
            old_processes = {process['pid']: process for process in self.processes}
            for item in flows + processes:
                old = previous.get(item['id'], {}) if 'id' in item else old_processes.get(item['pid'], {})
                for axis in ('rx', 'tx'):
                    item[axis + '_bps'] = rate(item.get(axis + '_bytes'), old.get(axis + '_bytes'), elapsed)
                item['last_seen'] = time.time()
            self.flows, self.processes = flows[:2000], processes[:1000]
            self._flow_time = now
            self.updated_at = time.time()

    def add_packet(self, packet):
        with self.lock:
            self.capture['packets'] += 1
            self.capture['bytes'] += packet['length']
            packet['id'] = self.capture['packets']
            local = set(self.machine['addresses'])
            src, dst = packet['src_ip'], packet['dst_ip']
            src_local = src in local or ipaddress.ip_address(src).is_loopback
            dst_local = dst in local or ipaddress.ip_address(dst).is_loopback
            direction = 'local' if src_local and dst_local else 'out' if src_local else 'in' if dst_local else 'other'
            packet['direction'] = direction
            packet['interface'] = self.capture['interface']
            self.packets.append(packet)
            self.protocols[packet['protocol']] += 1
            if direction in ('in', 'out', 'local'):
                out = direction in ('out', 'local')
                key = (packet['protocol'], src if out else dst,
                       packet.get('src_port') if out else packet.get('dst_port'),
                       dst if out else src, packet.get('dst_port') if out else packet.get('src_port'))
                item = self.capture_flows.pop(key, {'packets': 0, 'captured_bytes': 0,
                                                   'captured_rx': 0, 'captured_tx': 0})
                item['packets'] += 1
                item['captured_bytes'] += packet['length']
                item['captured_tx' if out else 'captured_rx'] += packet['length']
                item['last_seen'] = time.time()
                self.capture_flows[key] = item
                if len(self.capture_flows) > 2000:
                    self.capture_flows.popitem(last=False)

    def get_packet(self, packet_id):
        with self.lock:
            return next((dict(packet) for packet in reversed(self.packets) if packet['id'] == packet_id), None)

    def observed_target(self, target):
        with self.lock:
            return (any(flow['remote_ip'] == target for flow in self.flows)
                    or any(target in (packet['src_ip'], packet['dst_ip']) for packet in self.packets))

    def snapshot(self):
        with self.lock:
            selected = self.machine.get('default_interface') if self.selected_interface == 'auto' else self.selected_interface
            info = {name: {**self.interface_info.get(name, {}), **self.interfaces.get(name, {})}
                    for name in dict.fromkeys(list(self.interface_info) + list(self.interfaces))}
            metrics = dict(self.interfaces.get(selected, {}))
            if self.sources.get('counters', {}).get('available') is False:
                metrics['rx_bps'] = metrics['tx_bps'] = None
            flows = [dict(flow) for flow in self.flows]
            processes = [dict(process) for process in self.processes]
            if self.sources.get('connections', {}).get('available') is False:
                for item in flows + processes:
                    item.update(rx_bps=None, tx_bps=None, stale=True)
            indexed = {}
            for flow in flows:
                key = tuple(flow.get(k) for k in ('protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port'))
                indexed.setdefault(key, []).append(flow)
            for key, value in self.capture_flows.items():
                if key in indexed:
                    # Shared sockets can have multiple owners; do not duplicate capture counts.
                    indexed[key][0].update(value)
                elif time.time() - value['last_seen'] < 120:
                    proto, local_ip, local_port, remote_ip, remote_port = key
                    flows.append({'id': 'capture|' + repr(key), 'protocol': proto, 'local_ip': local_ip,
                                  'local_port': local_port, 'remote_ip': remote_ip, 'remote_port': remote_port,
                                  'pid': None, 'process': None, 'interface': self.capture['interface'],
                                  'source': 'capture', 'state': 'OBSERVED', 'rx_bytes': None,
                                  'tx_bytes': None, 'rx_bps': None, 'tx_bps': None, **value})
            flows.sort(key=lambda f: ((f.get('rx_bps') or 0) + (f.get('tx_bps') or 0),
                                      (f.get('rx_bytes') or 0) + (f.get('tx_bytes') or 0)), reverse=True)
            packets = [{k: v for k, v in packet.items() if k not in ('hex', 'ascii')}
                       for packet in list(self.packets)[-100:][::-1]]
            return copy.deepcopy({'timestamp': time.time(), 'updated_at': self.updated_at,
                                  'uptime': time.time() - self.started, 'machine': self.machine,
                                  'selected_interface': self.selected_interface, 'effective_interface': selected,
                                  'interfaces': list(info.values()), 'sources': self.sources,
                                  'metrics': {**metrics, 'interface': selected}, 'flows': flows[:500],
                                  'flow_count': len(flows), 'processes': processes,
                                  'capture': self.capture, 'packets': packets,
                                  'protocols': dict(self.protocols), 'traces': list(self.traces.values())})
