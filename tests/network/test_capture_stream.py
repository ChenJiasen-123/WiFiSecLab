import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import struct
import importlib.util
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from tests.protocol.test_eapol import FRAMES, PMK
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from wifiseclab.network.capture_stream import GrowingCapture, CaptureTransport
from wifiseclab.network.handshake_runner import run_handshake
from wifiseclab.protocol.wpa2_session import HandshakeSession


HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, 127)


def record(frame, seconds=1, radiotap=b'\x00\x00\x08\x00\x00\x00\x00\x00'):
    packet = radiotap + frame
    return struct.pack('<IIII', seconds, 0, len(packet), len(packet)) + packet


class CaptureStreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'growing.pcap'
        self.path.write_bytes(b'')
        self.reader = GrowingCapture(self.path); self.addCleanup(self.reader.close)
        self.now = 0.

    def append(self, data):
        with self.path.open('ab') as stream:
            stream.write(data)

    def sleep(self, delay):
        self.now += delay

    def transport(self, submit=lambda frame: len(frame), cutoff=0):
        return CaptureTransport(self.reader, submit, not_before=cutoff,
                                clock=lambda: self.now, sleep=self.sleep)

    def test_partial_header_and_record_are_not_consumed_or_duplicated(self):
        self.append(HEADER[:10]); self.assertIsNone(self.reader.next_record())
        self.append(HEADER[10:] + record(FRAMES[0])[:20])
        self.assertIsNone(self.reader.next_record())
        self.assertEqual(self.reader.index, 0)
        self.append(record(FRAMES[0])[20:])
        self.assertEqual(self.reader.next_record(), (1, 1., FRAMES[0]))
        self.assertIsNone(self.reader.next_record())
        self.assertIsNone(self.reader.next_record())
        self.assertEqual(self.reader.index, 1)
        self.reader.finish()

    def test_bad_fcs_consumed_once_and_valid_next_record_delivered(self):
        bad = b'\x00\x00\x09\x00\x02\x00\x00\x00\x40'
        self.append(HEADER + record(FRAMES[0], radiotap=bad) + record(FRAMES[2]))
        self.assertEqual(self.reader.next_record(), (1, 1., None))
        self.assertEqual(self.reader.next_record(), (2, 1., FRAMES[2]))
        self.assertEqual(self.reader.stats['driver_bad_fcs'], 1)
        self.reader.finish()

    def test_shrink_and_corruption_poison_reader(self):
        self.append(HEADER + record(FRAMES[0]))
        self.reader.next_record()
        self.path.write_bytes(HEADER)
        with self.assertRaises(ValueError): self.reader.next_record()
        self.append(record(FRAMES[0]))
        with self.assertRaises(ValueError): self.reader.next_record()

    def test_incomplete_final_record_is_not_clean_eof(self):
        self.append(HEADER + record(FRAMES[0])[:-1])
        self.assertIsNone(self.reader.next_record())
        with self.assertRaises(ValueError): self.reader.finish()

    def test_capture_cutoff_clock_regression_and_poll_timeout(self):
        self.append(HEADER + record(FRAMES[0], 1) + record(FRAMES[2], 2))
        transport = self.transport(cutoff=2)
        self.assertEqual(transport.receive(.1), FRAMES[2])
        self.assertEqual(transport.last_record['packet_index'], 2)
        self.assertIsNone(transport.receive(.1))
        self.assertGreaterEqual(self.now, .1)
        self.append(record(FRAMES[0], 1))
        with self.assertRaises(OSError): transport.receive(.1)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
    def test_runner_reads_each_capture_message_once_with_trigger_hashes(self):
        self.append(HEADER + b''.join(record(frame) for frame in FRAMES))
        sent = []
        def submit(frame):
            sent.append(frame)
            return len(frame)
        session = HandshakeSession(association(), advertisement(), PMK, timeout=.2)
        with patch('wifiseclab.protocol.wpa2_session.secrets.token_bytes', return_value=FRAMES[1][49:81]):
            result = run_handshake(session, self.transport(submit), lambda: self.now)
        self.assertEqual(len(sent), 2)
        self.assertEqual(result['frames_received'], 4)
        self.assertEqual([r['trigger_received_ordinal'] for r in result['submissions']], [1, 3])
        self.assertEqual([r['trigger_capture_record']['packet_index'] for r in result['submissions']], [1, 3])
        self.assertTrue(all(r['trigger_frame_sha256'] for r in result['submissions']))
        self.assertFalse(result['over_air_transmission_confirmed'])

    def test_invalid_record_fails_runner_without_submit(self):
        self.append(HEADER + struct.pack('<IIII', 1, 0, 100, 101))
        result = run_handshake(HandshakeSession(association(), advertisement(), PMK),
                               self.transport(), lambda: self.now)
        self.assertEqual(result['stop_reason'], 'receive_error')
        self.assertEqual(result['submissions'], [])

    def test_big_endian_nanosecond_capture(self):
        self.path.write_bytes(struct.pack('>IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 4096, 127))
        packet = b'\x00\x00\x08\x00\x00\x00\x00\x00' + FRAMES[0]
        self.append(struct.pack('>IIII', 2, 500000000, len(packet), len(packet)) + packet)
        self.assertEqual(self.reader.next_record(), (1, 2.5, FRAMES[0]))
        self.reader.finish()

    def test_snapshot_limit_and_timestamp_fraction_are_strict(self):
        for size, original, fraction in ((4097, 4097, 0), (100, 101, 0), (100, 100, 1000000)):
            with self.subTest(size=size, original=original, fraction=fraction):
                path = Path(self.tmp.name) / f'bad-{size}-{original}-{fraction}.pcap'
                path.write_bytes(HEADER + struct.pack('<IIII', 1, fraction, size, original))
                with GrowingCapture(path) as reader:
                    with self.assertRaises(ValueError): reader.next_record()
