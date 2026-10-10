import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('lab_udp_collector',
    Path(__file__).resolve().parents[2] / 'tools/hwsim/hwsim_udp.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class UdpCollectorTests(unittest.TestCase):
    def test_server_listen_time_separate_from_data_receipt(self):
        token = '11' * 16
        sock = MagicMock()
        sock.recvfrom.return_value = (b'WiFiSecLab-request:' + bytes.fromhex(token), ('192.0.2.2', 51000))
        sock.getsockname.return_value = ('192.0.2.1', 49321)
        sock.sendto.side_effect = lambda payload, peer: len(payload)
        with patch.object(collector.socket, 'socket') as factory, patch.object(collector.time, 'time', side_effect=[1, 2, 3]):
            factory.return_value.__enter__.return_value = sock
            result = collector.exchange('server', '192.0.2.1', 49321, token)
        self.assertTrue(result['success'])
        self.assertEqual(result['listening_started_at'], 1)
        self.assertEqual(result['started_at'], 2)
        self.assertEqual(result['request_received_at'], 2)
        self.assertEqual(result['finished_at'], 3)
