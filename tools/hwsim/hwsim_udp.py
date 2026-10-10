#!/usr/bin/env python3
"""One bounded UDP challenge/response on explicitly chosen lab endpoints."""
import argparse
import json
import socket
import time
from pathlib import Path


def exchange(role, address, port, token, ready=None, timeout=3):
    if type(timeout) not in (int,float) or not 0 < timeout <= 15:
        raise ValueError('Invalid bounded UDP timeout')
    challenge = b'WiFiSecLab-request:' + bytes.fromhex(token)
    response = b'WiFiSecLab-response:' + bytes.fromhex(token)
    if len(bytes.fromhex(token)) != 16:
        raise ValueError('Expected 128-bit per-run challenge')
    result = {'role': role, 'started_at': time.time(), 'success': False,
              'token': token, 'application_payload_verified': False}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            if role == 'server':
                result['listening_started_at'] = result['started_at']
                sock.bind((address, port))
                if ready:
                    Path(ready).write_text('ready', encoding='ascii')
                payload, peer = sock.recvfrom(1024)
                # Data interval begins at receipt, not while waiting for a STA.
                result['started_at'] = time.time()
                result['request_received_at'] = result['started_at']
                result['peer'] = list(peer)
                result['local_endpoint'] = list(sock.getsockname())
                result['remote_endpoint'] = list(peer)
                if payload == challenge:
                    result['success'] = sock.sendto(response, peer) == len(response)
                    result['application_payload_verified'] = True
            else:
                sock.connect((address, port))
                result['local_endpoint'] = list(sock.getsockname())
                result['remote_endpoint'] = [address, port]
                sock.send(challenge)
                payload = sock.recv(1024)
                result['success'] = payload == response
                result['application_payload_verified'] = result['success']
    except OSError as exc:
        result['error_type'] = type(exc).__name__
    result['finished_at'] = time.time()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('server', 'client'))
    parser.add_argument('--address', required=True)
    parser.add_argument('--port', type=int, default=49321)
    parser.add_argument('--token', required=True)
    parser.add_argument('--ready')
    parser.add_argument('--timeout', type=float, default=3)
    args = parser.parse_args()
    report = exchange(args.role, args.address, args.port, args.token, args.ready, args.timeout)
    print(json.dumps(report), flush=True)
    raise SystemExit(0 if report['success'] else 1)
