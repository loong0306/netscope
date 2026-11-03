import socket
import struct
import unittest
from netshow.pcap import PcapDecoder, decode_packet


def ipv4(payload, protocol=6, fragment=0):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 42, fragment,
                       64, protocol, 0, socket.inet_aton('10.0.0.2'), socket.inet_aton('1.1.1.1')) + payload


def tcp():
    return struct.pack('!HHIIBBHHH', 51234, 443, 100, 200, 0x50, 0x18, 65535, 0, 0) + b'hello'


def ethernet(payload, kind=0x0800):
    return bytes.fromhex('001122334455aabbccddeeff') + struct.pack('!H', kind) + payload


def pcap(data, linktype=1, wirelen=None, endian='<', nano=False):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    return (struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 256, linktype)
            + struct.pack(endian + 'IIII', 1700000000, 500000000 if nano else 500000,
                          len(data), wirelen or len(data)) + data)


def record(data, linktype=1, wirelen=None):
    return {'timestamp': 1700000000.5, 'length': wirelen or len(data),
            'data': data, 'linktype': linktype}


class PacketTests(unittest.TestCase):
    def test_tcp_packet_headers_and_original_length(self):
        value = decode_packet(record(ethernet(ipv4(tcp())), wirelen=1514))
        self.assertEqual((value['src_ip'], value['dst_ip'], value['src_port'], value['dst_port']),
                         ('10.0.0.2', '1.1.1.1', 51234, 443))
        self.assertEqual((value['length'], value['captured_length']), (1514, 59))
        self.assertEqual(value['tcp_flags'], ['PSH', 'ACK'])
        self.assertTrue(value['truncated'])
        self.assertTrue(value['hex'].endswith('68656c6c6f'))

    def test_ipv6_extension_header_udp(self):
        payload = struct.pack('!HHHH', 53000, 53, 8, 0)
        ext = bytes([17, 0]) + b'\x00' * 6
        header = struct.pack('!IHBB16s16s', 6 << 28, len(ext + payload), 0, 55,
                             socket.inet_pton(socket.AF_INET6, 'fd00::1'),
                             socket.inet_pton(socket.AF_INET6, '2606:4700:4700::1111'))
        value = decode_packet(record(header + ext + payload, 101))
        self.assertEqual(value['family'], 'IPv6')
        self.assertEqual(value['protocol'], 'UDP')
        self.assertEqual(value['dst_port'], 53)
        self.assertEqual(value['ttl'], 55)

    def test_vlan_and_loopback(self):
        vlan = ethernet(struct.pack('!HH', 1, 0x0800) + ipv4(tcp()), 0x8100)
        self.assertEqual(decode_packet(record(vlan))['src_port'], 51234)
        loop = struct.pack('<I', 2) + ipv4(tcp())
        self.assertEqual(decode_packet(record(loop, 0))['dst_ip'], '1.1.1.1')

    def test_ipv4_later_fragment_does_not_invent_tcp_ports(self):
        value = decode_packet(record(ipv4(b'\x00\x35\x01\xbb' + b'x' * 24, fragment=1), 101))
        self.assertTrue(value['fragment'])
        self.assertIsNone(value['src_port'])
        self.assertIsNone(value['dst_port'])

    def test_short_transport_and_invalid_ip_are_safe(self):
        self.assertIsNone(decode_packet(record(b'x')))
        value = decode_packet(record(ipv4(b'\x00\x35'), 101))
        self.assertIsNone(value['src_port'])
        self.assertEqual(value['protocol'], 'TCP')
        self.assertIsNone(decode_packet(record(ethernet(b'\x40' + b'\x00' * 30))))

    def test_linux_cooked_packet(self):
        cooked = struct.pack('!HHH8sH', 0, 1, 6, b'\x00' * 8, 0x0800) + ipv4(tcp())
        self.assertEqual(decode_packet(record(cooked, 113))['dst_port'], 443)

    def test_ipv6_fragment_does_not_read_ports(self):
        frag = bytes([6, 0]) + struct.pack('!H', 8) + struct.pack('!I', 7)
        payload = frag + b'\x00\x35\x01\xbb' + b'x' * 20
        header = struct.pack('!IHBB16s16s', 6 << 28, len(payload), 44, 64,
                             socket.inet_pton(socket.AF_INET6, 'fd00::1'),
                             socket.inet_pton(socket.AF_INET6, 'fd00::2'))
        value = decode_packet(record(header + payload, 101))
        self.assertTrue(value['fragment'])
        self.assertIsNone(value['dst_port'])


class PcapTests(unittest.TestCase):
    def test_streaming_waits_for_complete_records(self):
        raw = pcap(ethernet(ipv4(tcp())))
        decoder = PcapDecoder()
        self.assertEqual(decoder.feed(raw[:30]), [])
        self.assertEqual(decoder.feed(raw[30:-1]), [])
        result = decoder.feed(raw[-1:])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['timestamp'], 1700000000.5)
        self.assertEqual(decode_packet(result[0])['src_port'], 51234)
        self.assertEqual(decoder.feed(b''), [])

    def test_big_endian_nanosecond_capture(self):
        result = PcapDecoder().feed(pcap(ipv4(tcp()), 101, endian='>', nano=True))
        self.assertEqual(result[0]['timestamp'], 1700000000.5)

    def test_oversized_and_invalid_header_are_rejected(self):
        with self.assertRaises(ValueError):
            PcapDecoder().feed(b'not a pcap stream at all!')
        raw = pcap(b'x')[:24] + struct.pack('<IIII', 1, 1, 0x7fffffff, 0x7fffffff)
        with self.assertRaises(ValueError):
            PcapDecoder().feed(raw)

    def test_many_records_in_a_single_read(self):
        raw = pcap(ipv4(tcp()), 101)
        records = PcapDecoder().feed(raw + raw[24:] * 2)
        self.assertEqual(len(records), 3)


if __name__ == '__main__':
    unittest.main()
