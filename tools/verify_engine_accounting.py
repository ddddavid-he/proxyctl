#!/usr/bin/env python3
"""Real loopback TCP/UDP forwarding: close every flow before reading statistics."""
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive(sock, size):
    result = b''
    while len(result) < size:
        data = sock.recv(size-len(result))
        if not data:
            raise RuntimeError('unexpected EOF')
        result += data
    return result


def socks(proxy_port, command, host, target_port):
    sock = socket.create_connection(('127.0.0.1', proxy_port), timeout=5)
    sock.sendall(b'\x05\x01\x00')
    assert receive(sock, 2) == b'\x05\x00'
    address = host.encode()
    sock.sendall(bytes([5, command, 0, 3, len(address)]) + address + struct.pack('!H', target_port))
    reply = receive(sock, 4)
    assert reply[:2] == b'\x05\x00', reply
    address = receive(sock, 4 if reply[3] == 1 else 16)
    bind_port = struct.unpack('!H', receive(sock, 2))[0]
    return sock, bind_port


def http_payload(proxy_port, target_port):
    sock, _ = socks(proxy_port, 1, 'accounting.example.test', target_port)
    try:
        sock.sendall(b'GET / HTTP/1.0\r\nHost: accounting.example.test\r\n\r\n')
        data = b''
        while chunk := sock.recv(65536):
            data += chunk
        return data
    finally:
        sock.close()


def verify(binary):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = b'x' * 32768
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    udp.settimeout(10)
    def echo():
        try:
            for _ in range(5):
                data, peer = udp.recvfrom(65535)
                udp.sendto(data, peer)
        finally:
            udp.close()
    udp_thread = threading.Thread(target=echo, daemon=True)
    udp_thread.start()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        spool = root/'spool'
        spool.mkdir()
        proxy_port, controller_port = port(), port()
        while controller_port == proxy_port:
            controller_port = port()
        config = root/'config.yaml'
        config.write_text(f'mixed-port: {proxy_port}\nexternal-controller: 127.0.0.1:{controller_port}\nmode: direct\nlog-level: error\nhosts:\n  accounting.example.test: 127.0.0.1\n')
        log = (root/'engine.log').open('w+')
        process = subprocess.Popen([str(binary), '-d', str(root), '-f', str(config)], env=dict(os.environ, PROXYCTL_ACCOUNTING_DIR=str(spool)), stdout=log, stderr=log)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def snapshot():
            with opener.open(f'http://127.0.0.1:{controller_port}/connections', timeout=2) as response:
                return json.load(response)
        try:
            readiness_attempts = 0
            deadline = time.monotonic() + 20
            # Listeners precede tunnel.OnRunning in the pinned engine startup.
            # Require one successful transfer before the strict test workload.
            while time.monotonic() < deadline:
                readiness_attempts += 1
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    snapshot()
                    if http_payload(proxy_port, server.server_port).endswith(b'x'*32768):
                        break
                except (OSError, RuntimeError, AssertionError):
                    pass
                time.sleep(.1)
            else:
                log.seek(0)
                raise RuntimeError("engine forwarding readiness timeout: " + log.read())
            for index in range(25):
                data = http_payload(proxy_port, server.server_port)
                assert data.endswith(b'x'*32768), f"TCP flow {index+1}: incomplete response ({len(data)} bytes)"
            control, relay_port = socks(proxy_port, 3, '0.0.0.0', 0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                host = b'accounting.example.test'
                header = b'\x00\x00\x00\x03' + bytes([len(host)]) + host + struct.pack('!H', udp.getsockname()[1])
                for _ in range(5):
                    client.sendto(header + b'payload'*100, ('127.0.0.1', relay_port))
                    data, _ = client.recvfrom(65535)
                    assert data.endswith(b'payload'*100)
            control.close()
            totals = snapshot()
            time.sleep(2.2)
            process.terminate()
            process.wait(timeout=10)
            up = down = 0
            domains = set()
            for path in spool.glob('*.json'):
                batch = json.loads(path.read_text())
                for row in batch['rows']:
                    up += row['upload']
                    down += row['download']
                    domains.add(row['domain'])
            assert (up, down) == (totals['uploadTotal'], totals['downloadTotal']), (up, down, totals)
            assert domains == {'accounting.example.test'}, domains
            assert down > 25*32768
            collector = Path(__file__).resolve().parents[1] / 'deploy/traffic/traffic.py'
            command = [sys.executable, str(collector), 'collect', '--db', str(root/'usage.sqlite3'), '--engine-spool', str(spool), '--once']
            subprocess.run(command, check=True)
            subprocess.run(command, check=True)
            with sqlite3.connect(root/'usage.sqlite3') as db:
                assert db.execute('SELECT SUM(upload),SUM(download) FROM buckets').fetchone() == (up, down)
                assert db.execute('SELECT SUM(upload),SUM(download) FROM domain_buckets').fetchone() == (up, down)
            return dict(tcp_short_connections=25, udp_datagrams=5, readiness_attempts=readiness_attempts, upload=up, download=down, exact_match=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            log.close()
            server.shutdown()
            server.server_close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    print(json.dumps(verify(parser.parse_args().binary.resolve())))
