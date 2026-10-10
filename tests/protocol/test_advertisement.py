import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import unittest
import tests.protocol.test_eapol as golden
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES
from tests.protocol.test_wpa2 import association
from tests.protocol.test_keydata import RSNE


def beacon(rsn=RSNE):
    ap = bytes.fromhex(AP.replace(':', ''))
    return b'\x80\x00\x00\x00' + bytes([255]) * 6 + ap + ap + bytes(2) + bytes(12) + rsn


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
class AdvertisementTests(unittest.TestCase):
    setUp = golden.EapolTests.setUp
    analyze = golden.EapolTests.analyze

    def test_bound_rsne_path_requires_both_management_contexts(self):
        result = self.analyze([beacon(), association(), *FRAMES], pmk=PMK, unwrap=True)
        self.assertTrue(result['rsne_bound_mic_verified_four_message_path_observed'])
        self.assertEqual(result['attempts'][0]['advertisement_evidence']['packet_index'], 1)
        self.assertTrue(result['attempts'][0]['m3_rsne_matches_advertisement'])
        self.assertFalse(result['ap_key_installation_confirmed'])

    def test_mismatch_cannot_pass_despite_valid_mic_and_wrap(self):
        changed = bytearray(RSNE); changed[-2] ^= 1
        result = self.analyze([beacon(bytes(changed)), association(), *FRAMES], pmk=PMK, unwrap=True)
        self.assertFalse(result['consistent_four_message_path_observed'])
        self.assertIn('m3_rsne_differs_from_observed_advertisement',
                      [a['reason'] for a in result['context_anomalies']])

    def test_missing_stale_or_conflicting_advertisements_remain_unbound(self):
        changed = bytearray(RSNE); changed[-2] ^= 1
        cases = ([association(), *FRAMES],
                 [(1, beacon()), (100, association()), *[(100, f) for f in FRAMES]],
                 [beacon(), beacon(bytes(changed)), association(), *FRAMES],
                 [beacon(), beacon(RSNE + b'\xf4\x01\x00'), association(), *FRAMES],
                 [beacon(), beacon(b'\x30\xff'), association(), *FRAMES])
        for frames in cases:
            result = self.analyze(frames, pmk=PMK, unwrap=True)
            self.assertFalse(result['rsne_bound_mic_verified_four_message_path_observed'])
            self.assertIsNone(result['attempts'][0]['advertisement_evidence'])

    def test_post_m1_advertisements_cannot_overwrite_snapshot(self):
        changed = bytearray(RSNE); changed[-2] ^= 1
        frames = [beacon(bytes(changed)), association(), FRAMES[0], beacon(), *FRAMES[1:]]
        result = self.analyze(frames, pmk=PMK, unwrap=True)
        self.assertFalse(result['consistent_four_message_path_observed'])
        self.assertEqual(result['attempts'][0]['advertisement_evidence']['rsne_hex'], bytes(changed)[2:].hex())

    def test_other_bssid_does_not_supply_context(self):
        other = bytearray(beacon()); other[10] ^= 2; other[16] ^= 2
        result = self.analyze([bytes(other), association(), *FRAMES], pmk=PMK, unwrap=True)
        self.assertIsNone(result['attempts'][0]['advertisement_evidence'])
