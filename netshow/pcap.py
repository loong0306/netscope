"""Bounded incremental classic-PCAP reader and deliberately small packet decoder."""

import ipaddress
import struct


class PcapDecoder:
    def __init__(self):
        self.buffer = bytearray()
        self.endian = None
        self.scale = 1000000
        self.linktype = None
        self.snaplen = 0

    def feed(self, data):
        self.buffer.extend(data)
        if self.endian is None:
            if len(self.buffer) < 24:
                return []
            formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000),
                       b'\xa1\xb2\xc3\xd4': ('>', 1000000),
                       b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
                       b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
            if bytes(self.buffer[:4]) not in formats:
                raise ValueError('需要 classic PCAP；macOS 全接口抓包请使用 -y RAW。')
            self.endian, self.scale = formats[bytes(self.buffer[:4])]
            major, minor, _, _, self.snaplen, network = struct.unpack(
                self.endian + 'HHIIII', self.buffer[4:24])
            self.linktype = network & 0xffff
            if (major, minor) != (2, 4) or not 1 <= self.snaplen <= 1048576:
                raise ValueError('无效或过大的 PCAP 文件头')
            if self.linktype not in (0, 1, 12, 101, 108, 113, 228, 229, 276):
                raise ValueError('不支持的链路层类型：%s' % self.linktype)
            del self.buffer[:24]
        records = []
        offset = 0
        while len(self.buffer) - offset >= 16:
            seconds, fraction, captured, original = struct.unpack_from(
                self.endian + 'IIII', self.buffer, offset)
            if captured > self.snaplen or captured > 1048576 or captured > original:
                raise ValueError('无效的 PCAP 包长度')
            if fraction >= self.scale:
                raise ValueError('无效的 PCAP 时间戳')
            if len(self.buffer) - offset < 16 + captured:
                break
            records.append({'timestamp': seconds + fraction / self.scale,
                            'length': original, 'linktype': self.linktype,
                            'data': bytes(self.buffer[offset + 16:offset + 16 + captured])})
            offset += 16 + captured
        if offset:
            del self.buffer[:offset]
        return records


def decode_packet(record):
    """Decode only bytes actually present; never infer ports from later fragments."""
    raw = record['data']
    linktype = record['linktype']
    offset = 0
    ether_type = None
    if linktype == 1:
        if len(raw) < 14:
            return None
        offset = 14
        ether_type = struct.unpack_from('!H', raw, 12)[0]
        for _ in range(4):
            if ether_type not in (0x8100, 0x88a8, 0x9100):
                break
            if len(raw) < offset + 4:
                return None
            ether_type = struct.unpack_from('!H', raw, offset + 2)[0]
            offset += 4
    elif linktype in (0, 108):
        offset = 4
    elif linktype == 113:
        if len(raw) < 16:
            return None
        ether_type = struct.unpack_from('!H', raw, 14)[0]
        offset = 16
    elif linktype == 276:
        if len(raw) < 20:
            return None
        ether_type = struct.unpack_from('!H', raw, 0)[0]
        offset = 20
    elif linktype not in (12, 101, 228, 229):
        return None
    data = raw[offset:]
    if not data:
        return None
    result = {'timestamp': record['timestamp'], 'length': record['length'],
              'captured_length': len(raw), 'truncated': len(raw) < record['length'],
              'src_port': None, 'dst_port': None, 'tcp_flags': [], 'fragment': False,
              'hex': raw[:256].hex(),
              'ascii': ''.join(chr(x) if 32 <= x < 127 else '.' for x in raw[:256])}
    if ether_type == 0x0806:
        if len(data) < 28 or data[4:6] != b'\x06\x04':
            return None
        result.update(family='IPv4', protocol='ARP', ttl=None,
                      src_ip=str(ipaddress.ip_address(data[14:18])),
                      dst_ip=str(ipaddress.ip_address(data[24:28])),
                      summary='ARP 地址解析')
        return result
    if ether_type not in (None, 0x0800, 0x86dd):
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        header_len = (data[0] & 15) * 4
        total = struct.unpack_from('!H', data, 2)[0]
        if header_len < 20 or header_len > len(data) or total < header_len:
            return None
        bits = struct.unpack_from('!H', data, 6)[0]
        later_fragment = bool(bits & 0x1fff)
        result.update(family='IPv4', ttl=data[8], fragment=bool(bits & 0x3fff),
                      src_ip=str(ipaddress.ip_address(data[12:16])),
                      dst_ip=str(ipaddress.ip_address(data[16:20])))
        proto = data[9]
        transport = data[header_len:min(len(data), total)]
    elif version == 6:
        if len(data) < 40:
            return None
        result.update(family='IPv6', ttl=data[7],
                      src_ip=str(ipaddress.ip_address(data[8:24])),
                      dst_ip=str(ipaddress.ip_address(data[24:40])))
        proto = data[6]
        position = 40
        declared = 40 + struct.unpack_from('!H', data, 4)[0]
        data = data[:declared] if declared > 40 else data
        later_fragment = False
        for _ in range(12):
            if proto not in (0, 43, 44, 51, 60):
                break
            if position + 2 > len(data):
                return None
            next_proto = data[position]
            if proto == 44:
                if position + 8 > len(data):
                    return None
                bits = struct.unpack_from('!H', data, position + 2)[0]
                later_fragment = bool(bits & 0xfff8)
                result['fragment'] = True
                size = 8
            elif proto == 51:
                size = (data[position + 1] + 2) * 4
            else:
                size = (data[position + 1] + 1) * 8
            position += size
            proto = next_proto
            if position > len(data):
                return None
            if later_fragment:
                break
        transport = data[position:]
    else:
        return None
    result['protocol'] = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 50: 'ESP',
                          58: 'ICMPv6'}.get(proto, 'IP/%s' % proto)
    if not later_fragment:
        if proto == 6 and len(transport) >= 20:
            header_size = (transport[12] >> 4) * 4
            if 20 <= header_size <= len(transport):
                result['src_port'], result['dst_port'] = struct.unpack_from('!HH', transport)
                result['tcp_flags'] = [name for bit, name in (
                    (1, 'FIN'), (2, 'SYN'), (4, 'RST'), (8, 'PSH'),
                    (16, 'ACK'), (32, 'URG'), (64, 'ECE'), (128, 'CWR')) if transport[13] & bit]
        elif proto == 17 and len(transport) >= 8:
            udp_len = struct.unpack_from('!H', transport, 4)[0]
            if udp_len >= 8:
                result['src_port'], result['dst_port'] = struct.unpack_from('!HH', transport)
        elif proto in (1, 58) and len(transport) >= 2:
            result['icmp_type'], result['icmp_code'] = transport[:2]
    flags = ', '.join(result['tcp_flags'])
    result['summary'] = (('后续分片 · ' if later_fragment else '') + result['protocol']
                         + (' · ' + flags if flags else ''))
    return result
