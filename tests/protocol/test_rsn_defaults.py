import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest
from tests.core.test_session import profile, SSID, AP, STA
from wifiseclab.network.hotspot import rsn_details
from wifiseclab.core.session import build_association


FULL = bytes.fromhex('0100000fac040100000fac040100000fac020000')


class RsnDefaultsTests(unittest.TestCase):
    def test_omission_at_complete_field_boundaries_is_valid(self):
        for length in (2, 6, 12, 18, 20):
            with self.subTest(length=length):
                raw = FULL[:length]
                result = rsn_details(raw)
                self.assertNotIn('rsn_parse_error', result)
                self.assertEqual(result['group_cipher'], '000fac04')
                self.assertEqual(result['pairwise_ciphers'], ['000fac04'])
                self.assertEqual(result['akm_suites'], ['000fac01' if length < 18 else '000fac02'])
                self.assertEqual(result['rsn_hex'], raw.hex())
                self.assertEqual(result['pmkid_count'], 0)

    def test_truncation_inside_fields_does_not_invoke_defaults(self):
        for length in (0, 1, 3, 4, 5, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 19, 21):
            raw = (FULL + b'\x00')[:length]
            self.assertIn('rsn_parse_error', rsn_details(raw), str(length))

    def test_omitted_akm_never_admits_psk_association(self):
        result = rsn_details(b'\x01\x00')
        self.assertEqual(result['akm_suites'], ['000fac01'])
        self.assertIn('akm_suites', result['rsn_defaulted_fields'])
        with self.assertRaises(ValueError):
            build_association(SSID, AP, STA, {**profile(), **result})

    def test_same_effective_parameters_preserve_distinct_wire_bytes(self):
        omitted, explicit = rsn_details(FULL[:-2]), rsn_details(FULL)
        for key in ('group_cipher', 'pairwise_ciphers', 'akm_suites', 'pmf_capable', 'pmf_required'):
            self.assertEqual(omitted[key], explicit[key])
        self.assertNotEqual(omitted['rsn_hex'], explicit['rsn_hex'])
        self.assertIn('rsn_capabilities', omitted['rsn_defaulted_fields'])
        self.assertNotIn('rsn_capabilities', explicit['rsn_defaulted_fields'])

    def test_pmf_default_group_management_cipher_and_explicit_override(self):
        pmf = FULL[:-2] + b'\x80\x00'
        result = rsn_details(pmf)
        self.assertEqual(result['group_management_cipher'], '000fac06')
        explicit = rsn_details(pmf + b'\x00\x00' + bytes.fromhex('000fac0b'))
        self.assertEqual(explicit['group_management_cipher'], '000fac0b')
        self.assertNotIn('group_management_cipher', explicit['rsn_defaulted_fields'])
        self.assertIn('rsn_parse_error', rsn_details(FULL[:-2] + b'\x40\x00'))

    def test_reserved_counts_and_incomplete_pmkid_lists_remain_invalid(self):
        for raw in (FULL[:6] + b'\x00\x00', FULL[:12] + b'\x00\x00',
                    FULL + b'\x01\x00' + bytes(15), FULL + b'\x00\x00' + bytes(3)):
            self.assertIn('rsn_parse_error', rsn_details(raw))
        result = rsn_details(FULL + b'\x01\x00' + bytes(16))
        self.assertNotIn('rsn_parse_error', result)
        self.assertEqual(result['pmkid_count'], 1)
