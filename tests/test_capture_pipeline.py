from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from netshow.capture import CaptureController
from netshow.state import NetworkState
from test_pcap import ethernet, ipv4, tcp, pcap


class CapturePipelineTests(unittest.TestCase):
    def test_fifo_decodes_real_pcap_bytes_and_stop_reaps_child(self):
        state = NetworkState()
        state.interface_info = {'lo0': {'name': 'lo0'}}
        state.machine['addresses'] = ['10.0.0.2']
        capture = CaptureController(state, 8765)
        raw = pcap(ethernet(ipv4(tcp())))
        def packet_writer(interface, output, username, port):
            code = ("import time; f=open(%r,'wb',buffering=0); "
                    "f.write(%r); time.sleep(.05); f.write(%r); time.sleep(5)") % (str(output), raw[:30], raw[30:])
            return ['/usr/bin/python3', '-c', code]
        # Replace only the privileged OS source, keeping FIFO I/O, decoder,
        # state, thread cancellation, and process ownership real.
        with patch('netshow.capture.build_capture_command', packet_writer):
            capture.start('lo0')
            try:
                deadline = time.monotonic() + 3
                while state.snapshot()['capture']['packets'] == 0 and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertEqual(state.snapshot()['capture']['packets'], 1)
                self.assertEqual(state.snapshot()['capture']['status'], 'running')
                self.assertEqual(state.get_packet(1)['dst_port'], 443)
                self.assertEqual(state.get_packet(1)['direction'], 'out')
                process = capture.process
            finally:
                capture.stop()
                capture.thread.join(timeout=3)
            self.assertFalse(capture.thread.is_alive())
            self.assertIsNotNone(process.poll())
            self.assertEqual(state.snapshot()['capture']['status'], 'stopped')


if __name__ == '__main__':
    unittest.main()

class CaptureCancellationTests(unittest.TestCase):
    def test_stop_during_process_creation_cancels_child_and_allows_restart(self):
        import subprocess
        state = NetworkState()
        state.interface_info = {'lo0': {'name': 'lo0'}}
        capture = CaptureController(state, 8765)
        entered, release = threading.Event(), threading.Event()
        children = []
        original_popen = subprocess.Popen
        def delayed_child(argv, **kwargs):
            # A real non-privileged child at the native authorization boundary.
            process = original_popen(['/bin/sleep', '10'], **kwargs)
            children.append(process)
            entered.set()
            release.wait(2)
            return process
        with patch('netshow.capture.subprocess.Popen', delayed_child):
            capture.start('lo0', authorize=True)
            stopper = None
            try:
                self.assertTrue(entered.wait(2))
                stopper = threading.Thread(target=capture.stop)
                stopper.start()
                self.assertTrue(capture.stopping.wait(1))
                release.set()
                stopper.join(2)
                capture.thread.join(.5)
                self.assertFalse(capture.thread.is_alive(), 'stop left authorization waiting and blocked restart')
                self.assertIsNotNone(children[0].poll())
                self.assertEqual(state.snapshot()['capture']['status'], 'stopped')
            finally:
                release.set()
                for process in children:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=2)
                capture.thread.join(2)
                if stopper:
                    stopper.join(2)
