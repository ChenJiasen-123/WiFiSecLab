import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import json
import unittest
from unittest.mock import patch
import tests.protocol.test_eapol as golden
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES
from wifiseclab.protocol.wpa2 import derive_kck, derive_kek, key_mic, unwrap_key_data


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
class KeyWrapTests(unittest.TestCase):
    setUp = golden.EapolTests.setUp
    analyze = golden.EapolTests.analyze

    def test_rfc3394_section_4_1_vector_and_integrity_failure(self):
        kek = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        wrapped = bytes.fromhex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5')
        self.assertEqual(unwrap_key_data(wrapped, kek), bytes.fromhex('00112233445566778899aabbccddeeff'))
        for damaged in (wrapped[:-1], bytes(24), bytes([wrapped[0] ^ 1]) + wrapped[1:]):
            with self.assertRaises(ValueError):
                unwrap_key_data(damaged, kek)

    def test_real_m3_unwrap_and_no_plaintext_in_report(self):
        ap, sta = bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', ''))
        kek = derive_kek(PMK, ap, sta, FRAMES[0][49:81], FRAMES[1][49:81])
        plaintext = unwrap_key_data(FRAMES[2][131:], kek)
        result = self.analyze(pmk=PMK, unwrap=True)
        self.assertTrue(result['mic_verified_four_message_path_observed'])
        self.assertTrue(result['attempts'][0]['m3_key_data_unwrap_valid'])
        self.assertEqual(result['events'][2]['unwrapped_key_data_length'], len(plaintext))
        self.assertNotIn(plaintext.hex(), json.dumps(result))
        self.assertNotIn(kek.hex(), json.dumps(result))
        self.assertFalse(result['ap_key_installation_confirmed'])

    def test_valid_mic_cannot_hide_failed_keywrap(self):
        ap, sta = bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', ''))
        kck = derive_kck(PMK, ap, sta, FRAMES[0][49:81], FRAMES[1][49:81])
        changed = bytearray(FRAMES[2]); changed[-1] ^= 1
        changed[113:129] = key_mic(changed[32:], kck)
        result = self.analyze([*FRAMES[:2], bytes(changed), FRAMES[3]], pmk=PMK, unwrap=True)
        self.assertTrue(result['events'][2]['mic_valid'])
        self.assertFalse(result['events'][2]['key_data_unwrap_valid'])
        self.assertFalse(result['consistent_four_message_path_observed'])

    def test_no_unwrap_before_mic_or_without_known_pmk(self):
        with self.assertRaises(ValueError):
            self.analyze(unwrap=True)
        with patch('wifiseclab.protocol.eapol.unwrap_key_data') as unwrap:
            self.analyze(pmk=bytes(32), unwrap=True)
            unwrap.assert_not_called()

    def test_valid_mic_and_wrap_do_not_imply_valid_keydata_contents(self):
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        from tests.protocol.test_keydata import RSNE, pad
        ap, sta = bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', ''))
        args = PMK, ap, sta, FRAMES[0][49:81], FRAMES[1][49:81]
        ciphertext = aes_key_wrap(derive_kek(*args), pad(RSNE))  # missing negotiated GTK
        changed = bytearray(FRAMES[2][:131] + ciphertext)
        changed[34:36] = (len(changed) - 36).to_bytes(2, 'big')
        changed[129:131] = len(ciphertext).to_bytes(2, 'big')
        changed[113:129] = key_mic(changed[32:], derive_kck(*args))
        result = self.analyze([*FRAMES[:2], bytes(changed), FRAMES[3]], pmk=PMK, unwrap=True)
        self.assertTrue(result['events'][2]['mic_valid'])
        self.assertTrue(result['events'][2]['key_data_unwrap_valid'])
        self.assertFalse(result['events'][2]['key_data_content_valid'])
        self.assertFalse(result['consistent_four_message_path_observed'])
