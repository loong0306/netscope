"""Explicitly authorized tcpdump capture. The web service never runs as root."""

import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from .pcap import PcapDecoder, decode_packet


def build_capture_command(interface, output, username, port):
    if interface != 'all' and not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,31}', interface):
        raise ValueError('无效的网卡名称')
    argv = ['/usr/sbin/tcpdump', '-i', 'pktap,all' if interface == 'all' else interface,
            '-p', '-n', '-U', '-s', '256', '-Z', username, '-w', str(output)]
    if interface == 'all':
        argv += ['-y', 'RAW']
    # Exclude the monitor's loopback HTTP/SSE so observation does not feed itself.
    argv.append('not (tcp port %d and (host 127.0.0.1 or host ::1))' % port)
    return argv


def background_command(argv, log_path):
    # AppleScript's non-interactive shell has no controlling console. Darwin
    # nohup can fail there while trying to detach. Redirect every inherited
    # stream instead, so `do shell script` returns without keeping a pipe open.
    return shlex.join(argv) + ' >/dev/null 2>' + shlex.quote(str(log_path)) + ' </dev/null & echo $!'


class CaptureController:
    def __init__(self, state, port):
        self.state, self.port = state, port
        self.lock = threading.RLock()
        self.thread = None
        self.stopping = threading.Event()
        self.process = None
        self.pid = None
        self.auth = None

    def start(self, interface, authorize=False):
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('采集正在运行或等待授权，请先停止当前采集。')
            if interface != 'all' and interface not in self.state.interface_info:
                raise ValueError('请选择本机已有的网卡')
            self.stopping = threading.Event()
            self.pid = self.process = self.auth = None
            with self.state.lock:
                self.state.capture.update(status='authorizing' if authorize else 'starting',
                                          message='请在 macOS 弹窗中授权 tcpdump' if authorize else '正在打开采集设备',
                                          interface=interface, dropped=None)
            self.thread = threading.Thread(target=self._worker, args=(interface, authorize),
                                           daemon=True, name='packet-capture')
            self.thread.start()

    def stop(self):
        self.stopping.set()
        with self.lock:
            if self.auth and self.auth.poll() is None:
                self.auth.terminate()
            try:
                if self.process and self.process.poll() is None:
                    self.process.terminate()
                elif self.pid:
                    # -Z relinquishes root before opening the FIFO.
                    os.kill(self.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=2.5)
        with self.state.lock:
            alive = self.thread is not None and self.thread.is_alive()
            self.state.capture.update(status='stopping' if alive else 'stopped',
                                      message='正在停止采集，请稍候' if alive else '采集已停止；已采集的包仍可查看')

    def _worker(self, interface, authorize):
        directory = Path(tempfile.mkdtemp(prefix='netscope-'))
        fifo, log_path = directory / 'packets.fifo', directory / 'capture.log'
        os.mkfifo(fifo, 0o600)
        log_fd = os.open(log_path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(log_fd)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        decoder = PcapDecoder()
        try:
            command = build_capture_command(interface, fifo, pwd.getpwuid(os.getuid()).pw_name, self.port)
            if authorize:
                shell = background_command(command, log_path)
                script = 'do shell script ' + json.dumps(shell) + ' with administrator privileges'
                with self.lock:
                    if self.stopping.is_set():
                        return
                    self.auth = subprocess.Popen(['/usr/bin/osascript', '-e', script],
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = self.auth.communicate(timeout=120)
                if self.auth.returncode:
                    raise RuntimeError('系统授权取消或失败：' + stderr.strip()[:180])
                if not stdout.strip().isdigit():
                    raise RuntimeError('未获取到 tcpdump 进程')
                self.pid = int(stdout.strip())
            else:
                with self.lock:
                    if self.stopping.is_set():
                        return
                    with log_path.open('ab') as log:
                        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
                                                        stdin=subprocess.DEVNULL)
                    self.pid = self.process.pid
            if self.stopping.is_set():
                try:
                    os.kill(self.pid, signal.SIGTERM)
                except OSError:
                    pass
                return
            started = time.monotonic()
            has_data = False
            while not self.stopping.is_set():
                ready, _, _ = select.select([reader], [], [], .25)
                chunk = os.read(reader, 65536) if ready else b''
                if chunk:
                    records = decoder.feed(chunk)
                    if decoder.linktype is not None and not has_data:
                        has_data = True
                        with self.lock, self.state.lock:
                            if self.stopping.is_set():
                                break
                            self.state.capture.update(status='running', message='正在采集真实数据包',
                                                      started_at=time.time())
                    for record in records:
                        packet = decode_packet(record)
                        if packet:
                            self.state.add_packet(packet)
                        else:
                            with self.state.lock:
                                self.state.capture['skipped'] += 1
                else:
                    # An unopened or closed FIFO is immediately readable: avoid a busy loop.
                    self.stopping.wait(.05)
                exited = self.process is not None and self.process.poll() is not None
                if self.process is None and self.pid:
                    try:
                        os.kill(self.pid, 0)
                    except ProcessLookupError:
                        exited = True
                if exited or (not has_data and time.monotonic() - started > 8):
                    message = log_path.read_text(errors='replace')[-1000:]
                    if 'permission' in message.lower() or 'permitted' in message.lower():
                        message = '抓包需要管理员权限。点击「系统授权抓包」并完成 macOS 认证。'
                    raise RuntimeError(message.strip() or 'tcpdump 未输出有效数据，请检查网卡或权限。')
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            if not self.stopping.is_set():
                with self.state.lock:
                    message = ('系统认证等待超时，请重新点击「系统授权抓包」，并在 macOS 弹窗中完成认证。'
                               if isinstance(error, subprocess.TimeoutExpired) else str(error)[:500])
                    self.state.capture.update(status='error', message=message)
        finally:
            os.close(reader)
            with self.lock:
                if self.process and self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                elif self.pid:
                    try:
                        os.kill(self.pid, signal.SIGTERM)
                    except OSError:
                        pass
                if self.auth and self.auth.poll() is None:
                    self.auth.terminate()
                    try:
                        self.auth.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.auth.kill()
                self.pid = self.process = self.auth = None
            if self.stopping.is_set():
                with self.state.lock:
                    self.state.capture.update(status='stopped', message='采集已停止；已采集的包仍可查看')
            shutil.rmtree(directory, ignore_errors=True)
