import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import tempfile
from pathlib import Path
import struct
import unittest
from unittest.mock import Mock
from types import SimpleNamespace
from tests.network.test_capture_stream import HEADER
from tests.protocol.test_eapol import FRAMES, PMK
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from tests.protocol.test_association_gate import response
from wifiseclab.network.handshake_handoff import ClockAnchor, prepare_handoff


def record(frame, fraction):
    packet = b'\x00\x00\x08\x00\x00\x00\x00\x00' + frame
    return struct.pack('<IIII', 1000, fraction, len(packet), len(packet)) + packet


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'air.pcap'
        self.adapter = SimpleNamespace(active=True, capture=Mock(), output=self.path.parent)
        self.adapter.capture.poll.return_value = None
        self.now, self.wall = 10.2, 1000.2
        self.anchor = ClockAnchor(1000., 10., 0.)

    def prepare(self):
        result = prepare_handoff(self.adapter, association(), advertisement(), PMK, self.anchor,
            clock=lambda: self.now, realtime=lambda: self.wall, sleep=lambda seconds: None)
        self.addCleanup(result[1].close)
        return result

    def test_buffered_m1_same_timestamp_survives_request_cursor(self):
        self.path.write_bytes(HEADER + record(association(), 0) + record(response(), 100000) +
                              record(FRAMES[0], 100000))
        session, transport = self.prepare()
        self.assertAlmostEqual(session.deadline, 20.2)
        evidence = session.report()['association_admission_evidence']
        self.assertAlmostEqual(evidence['responses'][0]['time'], 10.1)
        self.assertEqual(evidence['responses'][0]['capture_packet_index'], 2)
        self.assertEqual(transport.receive(.1), FRAMES[0])
        self.assertEqual(transport.last_record['packet_index'], 3)
        self.assertIsNotNone(session.receive(FRAMES[0], 10.2))

    def test_response_retry_after_m1_does_not_skip_buffered_m1(self):
        self.path.write_bytes(HEADER + record(association(), 0) + record(response(), 50000) +
                              record(FRAMES[0], 60000) + record(response(), 70000))
        session, transport = self.prepare()
        self.assertEqual(len(session.admission_evidence['responses']), 2)
        self.assertEqual(transport.after_record_index, 2)
        self.assertEqual(transport.receive(.1), FRAMES[0])

    def test_realtime_step_rejects_before_session_creation(self):
        self.wall += 1
        with self.assertRaisesRegex(ValueError, 'clock relationship changed'):
            self.prepare()

    def test_sampling_width_and_anchor_values_are_checked(self):
        ticks = iter([0., .1])
        with self.assertRaises(ValueError): ClockAnchor.sample(lambda: next(ticks), lambda: 1000.)
        for values in ((float('nan'), 0, 0), (1000, 0, 1), (1000, -1, 0)):
            with self.assertRaises(ValueError): ClockAnchor(*values)

    def test_partial_m1_stays_pending_until_complete_append(self):
        tail = record(FRAMES[0], 100000)
        self.path.write_bytes(HEADER + record(association(), 0) + record(response(), 50000) + tail[:20])
        _, transport = self.prepare()
        with self.path.open('ab') as stream: stream.write(tail[20:])
        self.assertEqual(transport.receive(.1), FRAMES[0])

    def test_late_boundary_rejects_even_with_prior_success(self):
        disconnect = bytearray(response()[:24]); disconnect[0] = 0xc0
        self.path.write_bytes(HEADER + record(association(), 0) + record(response(), 50000) +
                              record(bytes(disconnect) + b'\x03\x00', 100000))
        with self.assertRaises(ValueError): self.prepare()

    def test_clock_step_after_handoff_blocks_buffered_m1(self):
        self.path.write_bytes(HEADER + record(association(), 0) + record(response(), 50000) +
                              record(FRAMES[0], 100000))
        _, transport = self.prepare()
        self.wall += 1
        with self.assertRaises(OSError): transport.receive(.1)
