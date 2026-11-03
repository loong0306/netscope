"""Loopback HTTP/SSE API, same-origin controls and restricted static assets."""

import ipaddress
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import threading
import time
from urllib.parse import unquote, urlsplit

from .capture import CaptureController
from .system import parse_route, parse_trace, run

ROOT = Path(__file__).resolve().parent.parent


def trace_worker(state, target):
    result = {'target': target, 'status': 'running', 'hops': [], 'started_at': time.time()}
    with state.lock:
        state.traces[target] = result
        while len(state.traces) > 16:
            state.traces.popitem(last=False)
    try:
        family6 = ipaddress.ip_address(target).version == 6
        result['route'] = parse_route(run(['/sbin/route', '-n', 'get']
                                         + (['-inet6'] if family6 else []) + [target]))
        program = '/usr/sbin/traceroute6' if family6 else '/usr/sbin/traceroute'
        command = [program, '-n', '-m', '12', '-q', '1', '-w', '1', target]
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=18)
            output, error, code = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as expired:
            output = (expired.stdout or b'').decode(errors='replace')
            error, code = '探测超时，已保留收到的跳点。', 1
        hops = parse_trace(output)
        reached = any(hop['ip'] == target for hop in hops)
        with state.lock:
            result.update(status='complete' if reached else 'partial' if hops else 'error',
                          hops=hops, reached=reached, finished_at=time.time(),
                          message='目标已响应' if reached else error.strip()[:300] or
                          ('部分跳点未响应，路径可能受防火墙、VPN 或 ICMP 策略影响。' if hops else '未收到跳点响应'))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        with state.lock:
            result.update(status='error', message=str(error)[:300])


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_server(state, port=8765):
    server = LocalServer(('127.0.0.1', port), Handler)
    server.state = state
    server.token = secrets.token_urlsafe(32)
    server.capture = CaptureController(state, server.server_address[1])
    server.closed = threading.Event()
    server.trace_lock = threading.Lock()
    return server


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def valid_host(self):
        port = self.server.server_address[1]
        return self.headers.get('Host', '') in ('127.0.0.1:%d' % port, 'localhost:%d' % port)

    def json(self, value, status=200):
        body = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if not self.valid_host():
            return self.json({'error': '只接受本机访问'}, 403)
        path = unquote(urlsplit(self.path).path)
        state = self.server.state
        if path == '/api/config':
            return self.json({'token': self.server.token, 'version': '1.0.0'})
        if path == '/api/snapshot':
            return self.json(state.snapshot())
        if path.startswith('/api/packets/'):
            try:
                packet_id = int(path.rsplit('/', 1)[-1])
            except ValueError:
                return self.json({'error': '包编号无效'}, 400)
            packet = state.get_packet(packet_id)
            return self.json(packet if packet else {'error': '该包已超出内存保留范围'}, 200 if packet else 404)
        if path == '/api/events':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                while not self.server.closed.is_set():
                    payload = json.dumps(state.snapshot(), ensure_ascii=False, allow_nan=False)
                    self.wfile.write(('data: ' + payload + '\n\n').encode())
                    self.wfile.flush()
                    self.server.closed.wait(1)
            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                pass
            self.close_connection = True
            return
        assets = {'/': ROOT / 'web/index.html', '/index.html': ROOT / 'web/index.html',
                  '/vendor/three.module.js': ROOT / 'node_modules/three/build/three.module.js',
                  '/vendor/three.core.js': ROOT / 'node_modules/three/build/three.core.js',
                  '/vendor/OrbitControls.js': ROOT / 'node_modules/three/examples/jsm/controls/OrbitControls.js'}
        target = assets.get(path)
        if target is None and path in ('/app.js', '/topology.js', '/format.js', '/styles.css', '/favicon.svg'):
            target = ROOT / 'web' / path[1:]
        if target is None or not target.is_file():
            return self.json({'error': '未找到'}, 404)
        body = target.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', mimetypes.guess_type(str(target))[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        origin = self.headers.get('Origin')
        port = self.server.server_address[1]
        allowed_origin = origin in (None, 'http://127.0.0.1:%d' % port, 'http://localhost:%d' % port)
        if (not self.valid_host() or not allowed_origin or
                not secrets.compare_digest(self.headers.get('X-NetScope-Token', ''), self.server.token)):
            self.close_connection = True
            return self.json({'error': '请求需来自本机页面并携带会话令牌'}, 403)
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 8192:
                raise ValueError('请求过大')
            body = json.loads(self.rfile.read(size) or b'{}')
            if not isinstance(body, dict):
                raise ValueError('需要 JSON 对象')
            state = self.server.state
            path = urlsplit(self.path).path
            if path == '/api/interface':
                value = body.get('interface')
                with state.lock:
                    if value not in ('auto', 'all') and value not in state.interface_info:
                        raise ValueError('未知的网卡')
                    if value == 'all':
                        raise ValueError('流量统计请选择单个网卡；全接口仅用于抓包')
                    state.selected_interface = value
            elif path == '/api/capture/start':
                interface = body.get('interface') or state.snapshot()['effective_interface']
                if not isinstance(interface, str) or not isinstance(body.get('authorize', False), bool):
                    raise ValueError('无效的采集参数')
                self.server.capture.start(interface, body.get('authorize', False))
            elif path == '/api/capture/stop':
                self.server.capture.stop()
            elif path == '/api/trace':
                target = str(ipaddress.ip_address(body.get('target', '')))
                ip = ipaddress.ip_address(target)
                if ip.is_multicast or ip.is_unspecified or not state.observed_target(target):
                    raise ValueError('只允许探测已观测连接中的单播 IP')
                with self.server.trace_lock, state.lock:
                    if any(value['status'] == 'running' for value in state.traces.values()):
                        raise ValueError('已有链路探测进行中，请稍后再试')
                    state.traces[target] = {'target': target, 'status': 'running', 'hops': []}
                    threading.Thread(target=trace_worker, args=(state, target), daemon=True).start()
            else:
                return self.json({'error': '未找到'}, 404)
            return self.json({'ok': True})
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            return self.json({'error': str(error)}, 400)
        except OSError as error:
            return self.json({'error': str(error)}, 500)
