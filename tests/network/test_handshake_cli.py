import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from tests.protocol.test_eapol import AP, STA, PMK
from tests.protocol.test_m4 import advertisement
from tests.protocol.test_association_gate import response
from tests.network.test_capture_stream import HEADER
from tests.network.test_handshake_runner import SimulatedAP
from wifiseclab.network.hotspot import management
from wifiseclab.network.hotspot_cli import main


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
class HandshakeCliTests(unittest.TestCase):
    def simulate(self, mode='normal'):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); output = root / 'evidence'
            key = root / 'known.pmk'; key.write_bytes(PMK)
            tick = [10.]
            peer = SimulatedAP(); peer.queue.clear()
            adapter, guard = MagicMock(), MagicMock()
            adapter.output, adapter.actions, adapter.output_created = output, [], False
            adapter.cleanup_errors, guard.cleanup_errors = [], []
            adapter.capture = MagicMock(); adapter.capture.poll.return_value = None
            def append(frame):
                timestamp = 990 + tick[0]
                packet = b'\x00\x00\x08\x00\x00\x00\x00\x00' + frame
                seconds = int(timestamp)
                with (output / 'air.pcap').open('ab') as stream:
                    stream.write(struct.pack('<IIII', seconds, round((timestamp - seconds) * 1000000),
                                             len(packet), len(packet)) + packet)
            def enter():
                output.mkdir(); adapter.output_created = adapter.active = True
                (output / 'air.pcap').write_bytes(HEADER)
                beacon = bytearray(advertisement()); beacon[34:36] = struct.pack('<H', 0x431)
                beacon += b'\x01\x04\x82\x84\x8b\x96\x03\x01\x01'
                append(bytes(beacon))
                return adapter
            def leave(*args):
                adapter.active = False; adapter.capture.poll.return_value = 0
            def send(frame):
                append(frame)
                packet = management(frame)
                if packet and packet['subtype'] == 11:
                    reply = bytearray(response()[:24]); reply[0] = 0xb0
                    append(bytes(reply) + struct.pack('<HHH', 0, 2, 0))
                elif packet and packet['subtype'] == 0:
                    append(response()); from tests.protocol.test_eapol import FRAMES
                    append(FRAMES[0])
                else:
                    peer.submit(frame)
                    while peer.queue: append(peer.queue.pop(0))
                    if mode == 'capture_exit' and not peer.simulated_m4_mic_valid:
                        adapter.capture.poll.return_value = 1
                    if mode == 'late_conflict' and peer.simulated_m4_mic_valid:
                        append(response(status=17))
                action = {'kind': 'frame_submitted', 'bytes': len(frame),
                          'sha256': hashlib.sha256(frame).hexdigest()}
                adapter.actions.append(action)
                return action
            adapter.__enter__.side_effect = enter
            adapter.__exit__.side_effect = leave
            adapter.send.side_effect = send
            adapter.report.return_value = {'capture_error': None, 'capture_exit_code': 0, 'cleanup_errors': []}
            def sleep(seconds): tick[0] += seconds
            with contextlib.ExitStack() as stack:
                for target, value in (('sys.platform', 'linux'),):
                    stack.enter_context(patch('wifiseclab.network.hotspot_cli.' + target, value))
                stack.enter_context(patch('wifiseclab.network.hotspot_cli.os.geteuid', return_value=0, create=True))
                stack.enter_context(patch('wifiseclab.network.hotspot_cli.discover'))
                stack.enter_context(patch('wifiseclab.network.hotspot_cli.RadioRoles.bind'))
                stack.enter_context(patch('wifiseclab.network.hotspot_cli.PhysicalRadioAdapter', return_value=adapter))
                stack.enter_context(patch('wifiseclab.network.hotspot_cli.NetworkGuard', return_value=guard))
                stack.enter_context(patch('time.monotonic', side_effect=lambda: tick[0]))
                stack.enter_context(patch('time.time', side_effect=lambda: 990 + tick[0]))
                stack.enter_context(patch('time.sleep', side_effect=sleep))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                code = main(['handshake', '--ssid', 'WiFiSecLab-hwsim', '--bssid', AP, '--source', STA,
                    '--channel', '1', '--duration', '.2', '--pmk-file', str(key), '--output', str(output)])
            result = json.loads((output / 'hotspot-report.json').read_text(encoding='utf-8'))
            self.assertNotIn(PMK.hex(), json.dumps(result))
            adapter.__exit__.assert_called_once()
            guard.__exit__.assert_called_once()
            return code, result, peer.simulated_m4_mic_valid, len(adapter.actions)

    def test_complete_command_with_simulated_capture_and_peer(self):
        code, result, m4_valid, actions = self.simulate()
        self.assertEqual(code, 0, result.get('error'))
        self.assertTrue(m4_valid)
        self.assertEqual(actions, 4)
        self.assertTrue(result['eapol']['rsne_bound_mic_verified_four_message_path_observed'])
        self.assertFalse(result['eapol']['ap_authorization_confirmed'])
        self.assertEqual(len(result['handshake']['submissions']), 2)

    def test_capture_exit_returns_failure_and_cleans_up(self):
        code, result, m4_valid, actions = self.simulate('capture_exit')
        self.assertNotEqual(code, 0)
        self.assertFalse(m4_valid)
        self.assertEqual(actions, 3)
        self.assertEqual(result['handshake']['stop_reason'], 'receive_error')

    def test_final_conflicting_response_prevents_command_success(self):
        code, result, m4_valid, actions = self.simulate('late_conflict')
        self.assertNotEqual(code, 0)
        self.assertTrue(m4_valid)
        self.assertFalse(result['sequence']['association_response_confirmed'])

    def test_invalid_pmk_never_prepares_radio(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wrong.pmk'; path.write_bytes(b'not32')
            with patch('wifiseclab.network.hotspot_cli.PhysicalRadioAdapter') as factory, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['handshake', '--ssid', 'lab', '--bssid', AP, '--channel', '1',
                      '--pmk-file', str(path), '--output', str(Path(folder) / 'output')])
            factory.assert_not_called()
