import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import socket
import threading
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('hwsim_udp', Path(__file__).resolve().parents[2] / 'tools/hwsim/hwsim_udp.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class HwsimDataTests(unittest.TestCase):
    def test_client_requires_exact_challenge_response(self):
        token = '11' * 16
        for valid in (True, False):
            with self.subTest(valid=valid), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.bind(('127.0.0.1', 0))
                server.settimeout(3)
                seen = []
                def respond():
                    payload, peer = server.recvfrom(1024)
                    seen.append(payload)
                    reply = b'WiFiSecLab-response:' + bytes.fromhex(token if valid else '22' * 16)
                    server.sendto(reply, peer)
                worker = threading.Thread(target=respond)
                worker.start()
                result = helper.exchange('client', '127.0.0.1', server.getsockname()[1], token)
                worker.join(timeout=4)
                self.assertFalse(worker.is_alive())
                self.assertEqual(seen, [b'WiFiSecLab-request:' + bytes.fromhex(token)])
                self.assertEqual(result['success'], valid)
                self.assertEqual(result['application_payload_verified'], valid)

    def test_short_challenge_is_rejected_before_socket(self):
        with self.assertRaises(ValueError):
            helper.exchange('client', '127.0.0.1', 49321, '11')
