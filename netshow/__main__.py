import argparse
import signal
import threading

from .server import create_server
from .state import NetworkState
from .system import SystemCollector


def main():
    parser = argparse.ArgumentParser(description='NetScope 本机网络观测台')
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    state = NetworkState()
    server = create_server(state, args.port)
    collector = SystemCollector(state)
    collector.start()
    def stop(*_):
        server.closed.set()
        collector.stop()
        server.capture.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print('NetScope → http://127.0.0.1:%d' % server.server_address[1], flush=True)
    print('真实本机数据 · Ctrl+C 停止 · 抓包由页面触发系统授权', flush=True)
    try:
        server.serve_forever(poll_interval=.25)
    finally:
        server.closed.set()
        collector.stop()
        server.capture.stop()
        server.server_close()


if __name__ == '__main__':
    main()
