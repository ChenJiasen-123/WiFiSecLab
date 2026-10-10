import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import struct
import tempfile
from pathlib import Path
import unittest
import zlib
from tests.network.test_hotspot import AP, STA, SSID, beacon, response
from wifiseclab.network.capture import decode_radiotap
from wifiseclab.network.hotspot import analyze_capture, build_request, elements, rsn_details
from wifiseclab.network.physical import captured_records, management_frame_matches


def radiotap(frame, flags=0x10, extended=False, tsft=False):
    present = 2 | (1 if tsft else 0) | (0x80000000 if extended else 0)
    header = struct.pack('<BBHI', 0, 0, 0, present)
    if extended:
        header += bytes(4)
    if tsft:
        header += bytes((-len(header)) % 8) + bytes(8)
    header += bytes([flags])
    header = header[:2] + struct.pack('<H', len(header)) + header[4:]
    if flags & 0x10:
        frame += struct.pack('<I', zlib.crc32(frame))
    return header + frame


class CaptureQualityTests(unittest.TestCase):
    def test_fcs_is_metadata_driven_and_crc_verified(self):
        frame = build_request('auth', SSID, AP, STA)
        for extended in (False, True):
            for tsft in (False, True):
                stats = {}
                self.assertEqual(decode_radiotap(radiotap(frame, extended=extended, tsft=tsft), stats), frame)
                self.assertEqual(stats['fcs_verified'], 1)
        corrupt = bytearray(radiotap(frame))
        corrupt[-1] ^= 1
        stats = {}
        self.assertIsNone(decode_radiotap(corrupt, stats))
        self.assertEqual(stats['software_bad_fcs'], 1)
        self.assertIsNone(decode_radiotap(radiotap(frame, flags=0x50)))
        trailer = frame + b'abcd'
        self.assertEqual(decode_radiotap(radiotap(trailer, flags=0)), trailer)
        self.assertFalse(management_frame_matches(frame, trailer))

    def test_invalid_metadata_cannot_be_parsed_as_frame(self):
        for packet in (b'', bytes.fromhex('0000070000000000'),
                       bytes.fromhex('0000080000000080'), bytes.fromhex('0000080002000000'),
                       bytes.fromhex('0000080001000000'), bytes.fromhex('0100080000000000')):
            with self.assertRaises(ValueError):
                decode_radiotap(packet)

    def test_ie_boundaries_and_repeatable_vendor_elements(self):
        for data in (b'\x00', b'\x00\x02a', b'\x00\x01a\x00\x01b',
                     b'\x30\x00\x30\x00'):
            with self.assertRaises(ValueError):
                elements(data)
        self.assertEqual(elements(bytes.fromhex('dd0161dd0162'))[221], b'a')

    def test_rsn_optional_fields_must_be_complete(self):
        mandatory = bytes.fromhex('0100000fac040100000fac040100000fac02')
        for suffix in ('00', '4000', '00000100', '0000000001', '00000000000fac0400'):
            self.assertIn('rsn_parse_error', rsn_details(mandatory + bytes.fromhex(suffix)))
        valid = rsn_details(mandatory + bytes.fromhex('80000000000fac06'))
        self.assertNotIn('rsn_parse_error', valid)
        self.assertEqual(valid['group_management_cipher'], '000fac06')
        self.assertNotIn('rsn_parse_error', rsn_details(mandatory))

    def test_bad_fcs_and_malformed_beacons_do_not_prove_success(self):
        request = build_request('auth', SSID, AP, STA)
        frames = [radiotap(beacon() + b'\x30\x00'), radiotap(request),
                  radiotap(response(), flags=0x50)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'air.pcap'
            data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, 127)
            for i, frame in enumerate(frames):
                data += struct.pack('<IIII', 1, i * 1000, len(frame), len(frame)) + frame
            path.write_bytes(data)
            report = analyze_capture(path, SSID, AP, request)
            self.assertTrue(report['request_observed'])
            self.assertFalse(report['response_observed'])
            self.assertEqual(report['targets'], [])
            self.assertEqual(report['invalid_management'][0]['packet_index'], 1)
            self.assertEqual(report['capture_quality']['driver_bad_fcs'], 1)
            self.assertEqual(report['capture_quality']['pcap_records'], 3)
            # Complete record bytes can nevertheless be snaplen-truncated.
            data = bytearray(data)
            struct.pack_into('<I', data, 36, len(frames[0]) + 1)
            path.write_bytes(data)
            for live in (False, True):
                with self.assertRaisesRegex(ValueError, 'Snapshot-truncated'):
                    list(captured_records(path, allow_incomplete=live))
