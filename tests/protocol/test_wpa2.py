import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
"""Offline construction checked against an independently captured hwsim M2."""
import unittest
import tests.protocol.test_eapol as captured
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES, counter
from wifiseclab.core.session import build_association
from wifiseclab.protocol.wpa2 import build_m2, derive_kck, key_mic


def association():
    return build_association('WiFiSecLab-hwsim', AP, STA, {
        'ssid': 'WiFiSecLab-hwsim',
        'bssid': AP, 'group_cipher': '000fac04', 'pairwise_ciphers': ['000fac04'],
        'akm_suites': ['000fac02'], 'supported_rates_hex': '82848b96', 'capabilities': 0x431})


class ConstructionTests(unittest.TestCase):
    def test_captured_m2_byte_exact(self):
        reply = build_m2(FRAMES[0], association(), PMK, FRAMES[1][49:81], eapol_version=1)
        self.assertEqual(reply[32:], FRAMES[1][32:])

    def test_invalid_inputs_fail_closed(self):
        for options in ({'pmk': b'x'}, {'snonce': bytes(32)}, {'sequence': -1}, {'eapol_version': 4}):
            args = {'pmk': PMK, **options}
            with self.assertRaises(ValueError):
                build_m2(FRAMES[0], association(), **args)
        with self.assertRaises(ValueError):
            build_m2(FRAMES[2], association(), PMK)


class BranchTests(unittest.TestCase):
    setUp = captured.EapolTests.setUp
    analyze = captured.EapolTests.analyze
    def test_fresh_snonce_then_earlier_branch_m3(self):
        first = int.from_bytes(FRAMES[0][41:49], 'big')
        later_m1 = counter(FRAMES[0], first + 1)
        later_m2 = build_m2(later_m1, association(), PMK, b'\x55' * 32)
        kck = derive_kck(PMK, bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', '')),
                         FRAMES[0][49:81], FRAMES[1][49:81])
        replies = []
        for frame in FRAMES[2:]:
            revised = bytearray(counter(frame, first + 2))
            revised[113:129] = key_mic(revised[32:], kck)
            replies.append(bytes(revised))
        frames = [*FRAMES[:2], later_m1, later_m2, *replies]
        result = self.analyze(frames, pmk=PMK)
        self.assertTrue(result['mic_verified_four_message_path_observed'])
        self.assertEqual(len(result['attempts'][0]['snonce_candidates']), 2)
        self.assertEqual(result['attempts'][0]['snonce_hex'], FRAMES[1][49:81].hex())
        self.assertFalse(self.analyze(frames)['consistent_four_message_path_observed'])


class DerivationIdentityTests(unittest.TestCase):
    def test_all_key_slices_reject_invalid_pairwise_identities(self):
        from wifiseclab.protocol.wpa2 import derive_kek
        from wifiseclab.network.ccmp import derive_tk
        ap = bytes.fromhex(AP.replace(':', ''))
        sta = bytes.fromhex(STA.replace(':', ''))
        invalid = (None, True, AP, bytearray(ap), b'x', bytes(6),
                   bytes([255]) * 6, bytes.fromhex('01005e000001'))
        for derive in (derive_kck, derive_kek, derive_tk):
            for peer in invalid:
                for pair in ((peer, sta), (ap, peer)):
                    with self.subTest(derive=derive.__name__, pair=pair):
                        with self.assertRaises(ValueError):
                            derive(PMK, *pair, FRAMES[0][49:81], FRAMES[1][49:81])
            with self.assertRaises(ValueError):
                derive(PMK, ap, ap, FRAMES[0][49:81], FRAMES[1][49:81])

    def test_local_individual_addresses_remain_supported(self):
        from wifiseclab.protocol.wpa2 import derive_kek
        from wifiseclab.network.ccmp import derive_tk
        ap, sta = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        for derive in (derive_kck, derive_kek, derive_tk):
            self.assertEqual(len(derive(PMK, ap, sta, FRAMES[0][49:81], FRAMES[1][49:81])), 16)
