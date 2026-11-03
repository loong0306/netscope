import http.client
import json
import threading
import subprocess
from unittest.mock import patch
import unittest
from netshow.capture import build_capture_command
from netshow.server import create_server, trace_worker
from netshow.state import NetworkState


class CaptureCommandTests(unittest.TestCase):
    def test_single_interface_and_all_interface_classic_pcap(self):
        command = build_capture_command('en1', '/tmp/test.fifo', 'byron', 8765)
        self.assertEqual(command[command.index('-i') + 1], 'en1')
        self.assertIn('-p', command)
        self.assertEqual(command[command.index('-s') + 1], '256')
        self.assertEqual(command[command.index('-Z') + 1], 'byron')
        command = build_capture_command('all', '/tmp/test.fifo', 'byron', 8765)
        self.assertEqual(command[command.index('-y') + 1], 'RAW')
        with self.assertRaises(ValueError):
            build_capture_command('en1; touch /tmp/injected', '/tmp/test.fifo', 'byron', 8765)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = NetworkState()
        cls.state.interface_info = {'en1': {'name': 'en1'}}
        cls.server = create_server(cls.state, port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        conn.request(method, path, json.dumps(body) if body is not None else None, headers or {})
        response = conn.getresponse()
        data = response.read()
        status = response.status
        conn.close()
        return status, data

    def test_snapshot_is_actual_empty_state_not_demo_data(self):
        status, data = self.request('GET', '/api/snapshot')
        self.assertEqual(status, 200)
        result = json.loads(data)
        self.assertEqual(result['flows'], [])
        self.assertNotIn('rx_bps', result['metrics'])

    def test_writes_require_session_token_and_same_origin(self):
        status, _ = self.request('POST', '/api/interface', {'interface': 'en1'})
        self.assertEqual(status, 403)
        headers = {'X-NetScope-Token': self.server.token, 'Origin': 'https://evil.example'}
        status, _ = self.request('POST', '/api/interface', {'interface': 'en1'}, headers)
        self.assertEqual(status, 403)
        headers['Origin'] = 'http://127.0.0.1:%s' % self.port
        status, _ = self.request('POST', '/api/interface', {'interface': 'en1'}, headers)
        self.assertEqual(status, 200)

    def test_invalid_interface_and_unobserved_trace_rejected(self):
        headers = {'X-NetScope-Token': self.server.token}
        self.assertEqual(self.request('POST', '/api/interface', {'interface': 'bogus'}, headers)[0], 400)
        self.assertEqual(self.request('POST', '/api/trace', {'target': '1.1.1.1;id'}, headers)[0], 400)
        self.assertEqual(self.request('POST', '/api/trace', {'target': '1.1.1.1'}, headers)[0], 400)

    def test_host_rebinding_and_path_traversal_rejected(self):
        self.assertEqual(self.request('GET', '/api/snapshot', headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.request('GET', '/../package.json')[0], 404)
        self.assertEqual(self.request('GET', '/%2e%2e/package.json')[0], 404)


if __name__ == '__main__':
    unittest.main()


class TraceFamilyTests(unittest.TestCase):
    def test_ipv6_trace_uses_native_ipv6_route_family(self):
        state = NetworkState()
        def route_query(argv, **kwargs):
            if '-inet6' not in argv:
                raise RuntimeError('route: bad address: 2606:4700:4700::1111')
            return 'gateway: fe80::1%en1\ninterface: en1\n'
        def trace_query(argv, **kwargs):
            if argv[0] != '/usr/sbin/traceroute6':
                raise OSError('IPv6 requires traceroute6')
            return subprocess.CompletedProcess(argv, 0, ' 1  2606:4700:4700::1111  2.5 ms\n', '')
        with patch('netshow.server.run', route_query), patch('netshow.server.subprocess.run', trace_query):
            trace_worker(state, '2606:4700:4700::1111')
        result = state.snapshot()['traces'][0]
        self.assertEqual(result['status'], 'complete')
        self.assertTrue(result['reached'])
        self.assertEqual(result['route']['interface'], 'en1')
        self.assertEqual(result['hops'][0]['rtt_ms'], 2.5)
