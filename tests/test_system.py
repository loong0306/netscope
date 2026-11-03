import unittest
from netshow.system import parse_nettop, parse_netstat, parse_ifconfig, parse_lsof, parse_trace
from netshow.state import NetworkState

NETTOP = ''',interface,state,bytes_in,bytes_out,
Google Chrome H.42,,,12000,8000,
tcp4 10.0.0.2:53100<->1.1.1.1:443,en1,Established,1000,500,
udp6 fd00::1.53000<->2606:4700:4700::1111.53,utun8,,200,100,
udp4 *:5353<->*:*,en1,,700,50,
tcp6 *.5000<->*.*,,Listen,,,
'''


class SystemTests(unittest.TestCase):
    def test_parse_socket_counters_and_ipv6_without_wildcard_nodes(self):
        flows, processes = parse_nettop(NETTOP)
        self.assertEqual(len(flows), 2)
        self.assertEqual((flows[0]['remote_ip'], flows[0]['remote_port'], flows[0]['pid']), ('1.1.1.1', 443, 42))
        self.assertEqual(flows[0]['rx_bytes'], 1000)
        self.assertEqual(flows[1]['remote_ip'], '2606:4700:4700::1111')
        self.assertEqual(flows[1]['remote_port'], 53)
        self.assertEqual(processes[0]['rx_bytes'], 12000)

    def test_netstat_link_rows_do_not_double_count_address_rows(self):
        rows = parse_netstat('''Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
lo0 16384 <Link#1> 40 0 1000 50 0 2000 0
lo0 16384 127 127.0.0.1 40 - 1000 50 - 2000 -
en1 1500 <Link#2> aa:bb:cc:dd:ee:ff 12 0 900 4 0 400 0
''')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows['en1']['tx_bytes'], 400)
        self.assertEqual(rows['lo0']['rx_bytes'], 1000)

    def test_ifconfig_addresses_and_status(self):
        rows = parse_ifconfig('''en1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
\tinet 10.0.0.2 netmask 0xffffff00
\tinet6 fe80::1234%en1 prefixlen 64
\tstatus: active
''')
        self.assertEqual(rows['en1']['addresses'], ['10.0.0.2', 'fe80::1234'])
        self.assertTrue(rows['en1']['active'])

    def test_lsof_ipv6_fallback_is_real_but_has_no_byte_counts(self):
        rows = parse_lsof('p42\ncChrome\nf12\nPTCP\nn[::1]:50000->[::1]:443\nTST=ESTABLISHED\n')
        self.assertEqual(rows[0]['local_ip'], '::1')
        self.assertIsNone(rows[0]['rx_bytes'])
        self.assertEqual(rows[0]['source'], 'lsof')

    def test_trace_keeps_unknown_hops(self):
        hops = parse_trace('traceroute to 1.1.1.1\n 1  10.0.0.1  1.234 ms\n 2  *\n 3  1.1.1.1  5.000 ms\n')
        self.assertEqual(hops[1], {'hop': 2, 'ip': None, 'rtt_ms': None})
        self.assertEqual(hops[2]['rtt_ms'], 5.0)


class StateTests(unittest.TestCase):
    def test_first_sample_and_counter_reset_do_not_create_rate_spikes(self):
        state = NetworkState()
        flow = parse_nettop(NETTOP)[0][0]
        state.update_flows([flow], [], now=10)
        self.assertIsNone(state.snapshot()['flows'][0]['rx_bps'])
        newer = dict(flow, rx_bytes=1200, tx_bytes=600)
        state.update_flows([newer], [], now=12)
        self.assertEqual(state.snapshot()['flows'][0]['rx_bps'], 100)
        state.update_flows([dict(flow, rx_bytes=10)], [], now=14)
        self.assertIsNone(state.snapshot()['flows'][0]['rx_bps'])

    def test_failed_collector_invalidates_flow_and_process_rates(self):
        state = NetworkState()
        flows, processes = parse_nettop(NETTOP)
        state.update_flows(flows, processes, now=10)
        flows, processes = parse_nettop(NETTOP.replace('1000,500', '1200,600').replace('12000,8000', '12400,8200'))
        state.update_flows(flows, processes, now=12)
        self.assertEqual(state.snapshot()['flows'][0]['rx_bps'], 100)
        state.set_source('connections', False, 'collector unavailable')
        snapshot = state.snapshot()
        self.assertIsNone(snapshot['flows'][0]['rx_bps'])
        self.assertIsNone(snapshot['processes'][0]['rx_bps'])
        self.assertTrue(snapshot['flows'][0]['stale'])

    def test_packet_ring_bounded_and_packet_ids_remain_monotonic(self):
        state = NetworkState()
        state.machine['addresses'] = ['10.0.0.2']
        for _ in range(605):
            state.add_packet({'timestamp': 1, 'length': 60, 'captured_length': 60,
                              'src_ip': '10.0.0.2', 'dst_ip': '1.1.1.1',
                              'src_port': 50000, 'dst_port': 443, 'protocol': 'TCP',
                              'hex': '00', 'ascii': '.'})
        snapshot = state.snapshot()
        self.assertEqual(snapshot['capture']['packets'], 605)
        self.assertIsNone(state.get_packet(1))
        self.assertEqual(state.get_packet(605)['direction'], 'out')
        self.assertEqual(len(state.packets), 600)
        self.assertNotIn('hex', snapshot['packets'][0])

    def test_interface_rates_are_not_summed_across_vpn(self):
        state = NetworkState()
        state.machine['default_interface'] = 'en1'
        state.update_interfaces({'en1': {'rx_bytes': 1000, 'tx_bytes': 2000},
                                 'utun8': {'rx_bytes': 1000, 'tx_bytes': 2000}}, now=10)
        state.update_interfaces({'en1': {'rx_bytes': 1400, 'tx_bytes': 2200},
                                 'utun8': {'rx_bytes': 1400, 'tx_bytes': 2200}}, now=12)
        self.assertEqual(state.snapshot()['metrics']['rx_bps'], 200)
        state.selected_interface = 'utun8'
        self.assertEqual(state.snapshot()['metrics']['tx_bps'], 100)


if __name__ == '__main__':
    unittest.main()
