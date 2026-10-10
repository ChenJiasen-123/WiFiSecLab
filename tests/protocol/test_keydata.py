import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import json
import unittest
from wifiseclab.protocol.keydata import parse_m3_key_data

RSNE = bytes.fromhex('30140100000fac040100000fac040100000fac020000')
SECRET = b'\x73' * 16
GTK = b'\xdd\x16\x00\x0f\xac\x01\x01\x00' + SECRET


def pad(data):
    if len(data) < 16 or len(data) % 8:
        data += b'\xdd'
        data += bytes((-len(data)) % 8)
        if len(data) < 16:
            data += bytes(16 - len(data))
    return data


class KeyDataTests(unittest.TestCase):
    def test_ccmp_metadata_padding_and_no_key_disclosure(self):
        result = parse_m3_key_data(pad(RSNE + GTK))
        self.assertTrue(result['baseline_profile_supported'])
        self.assertEqual(result['gtk']['key_length'], 16)
        self.assertEqual(result['gtk']['key_id'], 1)
        self.assertTrue(result['gtk']['reserved_zero'])
        self.assertEqual(result['padding_length'], 2)
        self.assertNotIn(SECRET.hex(), json.dumps(result))

    def test_second_rsne_is_unsupported_not_malformed(self):
        result = parse_m3_key_data(pad(RSNE + RSNE + GTK))
        self.assertFalse(result['baseline_profile_supported'])
        self.assertEqual(len(result['rsne_hex']), 2)

    def test_truncation_missing_gtk_and_duplicate_gtk_fail(self):
        for data in (pad(RSNE), pad(RSNE + GTK + GTK), pad(GTK),
                     pad(RSNE + b'\xdd\xfe'), pad(RSNE + b'\xdd\x15' + GTK[2:-1])):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                parse_m3_key_data(data)

    def test_unknown_elements_are_ignored_and_rsnxe_marks_unsupported(self):
        result = parse_m3_key_data(pad(RSNE + GTK + b'\xdd\x04\x12\x34\x56\x78'))
        self.assertEqual(result['unknown_elements_ignored'], 1)
        self.assertTrue(result['baseline_profile_supported'])
        self.assertFalse(parse_m3_key_data(pad(RSNE + GTK + b'\xf4\x01\x00'))
                         ['baseline_profile_supported'])

    def test_padding_marker_does_not_hide_nonzero_trailing_bytes(self):
        data = pad(RSNE + GTK)
        self.assertEqual(data[-2:], b'\xdd\x00')
        damaged = data + b'\x01' + bytes(7)
        with self.assertRaises(ValueError):
            parse_m3_key_data(damaged)
