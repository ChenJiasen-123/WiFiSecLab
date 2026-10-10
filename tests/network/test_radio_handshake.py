import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, MagicMock, patch
from tests.network.test_capture_stream import HEADER, record
from tests.protocol.test_eapol import FRAMES, PMK
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from tests.protocol.test_association_gate import response
from tests.network.test_handshake_runner import SimulatedAP
from wifiseclab.protocol.association_gate import admitted_session
from wifiseclab.protocol.wpa2_session import HandshakeSession
from wifiseclab.network.physical import PhysicalRadioAdapter
from wifiseclab.network.radio_handshake import PhysicalHandshakeTransport
from wifiseclab.network.handshake_runner import run_handshake


class PhysicalHandshakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)
        (self.output / 'air.pcap').write_bytes(HEADER + record(FRAMES[0]))
        self.factory = MagicMock()
        self.tx = self.factory.return_value.__enter__.return_value
        self.adapter = PhysicalRadioAdapter(None, self.output, socket_factory=self.factory)
        self.adapter.active = True
        self.adapter.capture = Mock()
        self.adapter.capture.poll.return_value = None
        self.now = .002
        self.session = admitted_session(association(), advertisement(), PMK,
            [(0., association()), (.001, response())], now=self.now, timeout=.2)

    def sleep(self, delay): self.now += delay

    def bridge(self):
        transport = PhysicalHandshakeTransport(self.adapter, self.session, not_before=1,
            clock=lambda: self.now, sleep=self.sleep)
        self.addCleanup(transport.close)
        return transport

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
    @patch('wifiseclab.network.physical.socket.AF_PACKET', 17, create=True)
    def test_fresh_snonce_loop_through_real_adapter_code_with_mock_socket(self):
        peer = SimulatedAP(); peer.queue.clear()
        def send(packet):
            self.assertEqual(packet[:8], b'\x00\x00\x08\x00\x00\x00\x00\x00')
            peer.submit(packet[8:])
            with (self.output / 'air.pcap').open('ab') as stream:
                while peer.queue:
                    stream.write(record(peer.queue.pop(0)))
            return len(packet)
        self.tx.send.side_effect = send
        transport = self.bridge()
        result = run_handshake(self.session, transport, lambda: self.now)
        self.assertTrue(peer.simulated_m4_mic_valid)
        self.assertEqual(len(self.adapter.actions), 2)
        self.assertEqual([row['adapter_action_index'] for row in transport.submission_actions], [0, 1])
        self.assertTrue(all(row['submission_complete'] for row in result['submissions']))
        self.assertFalse(result['over_air_transmission_confirmed'])
        self.assertEqual(self.tx.settimeout.call_args_list, [unittest.mock.call(.5)] * 2)
        self.assertTrue(all(row['over_air_observed'] is None for row in self.adapter.actions))

    @patch('wifiseclab.network.physical.socket.AF_PACKET', 17, create=True)
    def test_partial_or_timed_out_send_stops_without_retry(self):
        for outcome in (1, TimeoutError('private error')):
            with self.subTest(outcome=type(outcome).__name__):
                self.setUp()
                if isinstance(outcome, Exception): self.tx.send.side_effect = outcome
                else: self.tx.send.return_value = outcome
                result = run_handshake(self.session, self.bridge(), lambda: self.now)
                self.assertEqual(self.tx.send.call_count, 1)
                self.assertEqual(result['stop_reason'], 'submission_error')
                self.assertEqual(self.adapter.actions, [])
                self.assertNotIn('private error', str(result))

    def test_capture_exit_blocks_buffered_frames_and_submissions(self):
        transport = self.bridge()
        self.adapter.capture.poll.return_value = 1
        result = run_handshake(self.session, transport, lambda: self.now)
        self.assertEqual(result['stop_reason'], 'receive_error')
        self.factory.assert_not_called()
        with self.assertRaises(OSError): transport.submit(FRAMES[1])

    def test_admission_and_active_capture_required_before_reader_open(self):
        self.session = HandshakeSession(association(), advertisement(), PMK)
        with self.assertRaises(ValueError): self.bridge()
        self.setUp()
        self.adapter.capture = None
        with self.assertRaises(OSError): self.bridge()

    def test_only_outgoing_initial_peer_responses_are_submitted(self):
        transport = self.bridge()
        with self.assertRaises(ValueError): transport.submit(FRAMES[0])
        self.factory.assert_not_called()

    def test_send_timeout_configuration_is_bounded(self):
        for timeout in (None, True, 0, -1, float('nan'), float('inf'), 3):
            with self.assertRaises(ValueError):
                PhysicalRadioAdapter(None, self.output, send_timeout=timeout)

    @patch('wifiseclab.network.physical.socket.AF_PACKET', 17, create=True)
    def test_constructed_response_cannot_be_submitted_twice(self):
        transport = self.bridge()
        self.now = .003
        frame = self.session.receive(FRAMES[0], self.now)
        self.tx.send.return_value = len(frame) + 8
        self.assertEqual(transport.submit(frame), len(frame))
        with self.assertRaises(OSError): transport.submit(frame)
        self.assertEqual(self.tx.send.call_count, 1)
