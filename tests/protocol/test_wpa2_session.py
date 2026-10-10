import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import json
import unittest
from unittest.mock import patch
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES, counter, decode_key
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from wifiseclab.protocol.wpa2 import derive_kck, derive_kek, key_mic, unwrap_key_data
from wifiseclab.protocol.wpa2_session import HandshakeSession


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
class HandshakeSessionTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch('wifiseclab.protocol.wpa2_session.secrets.token_bytes', return_value=FRAMES[1][49:81])
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.session = HandshakeSession(association(), advertisement(), PMK, eapol_version=1)

    def sign_counter(self, frame, value):
        modified = bytearray(counter(frame, value))
        kck = derive_kck(PMK, bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', '')),
                         FRAMES[0][49:81], FRAMES[1][49:81])
        modified[113:129] = key_mic(modified[32:], kck)
        return bytes(modified)

    def test_event_driven_normal_path_matches_captured_responses(self):
        m2 = self.session.receive(FRAMES[0], .1)
        m4 = self.session.receive(FRAMES[2], .2)
        self.assertEqual(m2[32:], FRAMES[1][32:])
        self.assertEqual(m4[32:], FRAMES[3][32:])
        result = self.session.report()
        self.assertEqual(result['phase'], 'm4_constructed')
        for key in ('transmitted', 'key_installation_performed', 'ap_authorization_confirmed'):
            self.assertFalse(result[key])
        self.assertNotIn(PMK.hex(), json.dumps(result))

    def test_unauthenticated_high_m1_does_not_poison_valid_m3_floor(self):
        self.session.receive(FRAMES[0], .1)
        retry = self.session.receive(counter(FRAMES[0], 100), .2)
        self.assertEqual(decode_key(retry, AP, STA)['nonce_hex'], FRAMES[1][49:81].hex())
        self.assertIsNotNone(self.session.receive(FRAMES[2], .3))

    def test_tentative_anonce_replaced_and_legitimate_context_recovers(self):
        altered = bytearray(FRAMES[0])
        altered[49:81] = b'\x77' * 32
        self.assertIsNotNone(self.session.receive(bytes(altered), .1))
        m2 = self.session.receive(FRAMES[0], .2)
        self.assertIsNotNone(m2)
        self.assertEqual(m2[49:81], FRAMES[1][49:81])
        self.assertIsNotNone(self.session.receive(FRAMES[2], .3))
        report = self.session.report()
        limits = report['client_limitations']
        self.assertTrue(limits['different_anonce_m1_observed'])
        self.assertTrue(limits['different_anonce_recovery_supported'])
        self.assertFalse(limits['initial_anonce_pinned_from_unauthenticated_m1'])
        self.assertFalse(limits['ap_fault_inferred_from_anonce_change'])
        self.assertEqual(report['m4_responses_constructed'], 1)
        self.assertFalse(report['ap_authorization_confirmed'])

    def test_replaced_branch_m3_cannot_advance_authenticated_state(self):
        self.session.receive(FRAMES[0], .1)
        altered = bytearray(counter(FRAMES[0], 100))
        altered[49:81] = b'\x77' * 32
        self.assertIsNotNone(self.session.receive(bytes(altered), .2))
        self.assertIsNone(self.session.receive(FRAMES[2], .3))
        self.assertEqual(self.session.report()['m4_responses_constructed'], 0)
        # An unverified high counter must not establish the receive floor.
        self.assertIsNotNone(self.session.receive(FRAMES[0], .4))
        damaged = bytearray(FRAMES[2]); damaged[113] ^= 1
        self.assertIsNone(self.session.receive(bytes(damaged), .5))
        self.assertIsNotNone(self.session.receive(FRAMES[2], .6))

    def test_failed_m2_construction_preserves_previous_tentative_branch(self):
        self.session.receive(FRAMES[0], .1)
        altered = bytearray(FRAMES[0]); altered[49:81] = b'\x77' * 32
        with patch('wifiseclab.protocol.wpa2_session.build_m2', side_effect=ValueError):
            self.assertIsNone(self.session.receive(bytes(altered), .2))
        self.assertIsNotNone(self.session.receive(FRAMES[2], .3))

    def test_context_replacement_remains_bounded_by_response_budget(self):
        limited = HandshakeSession(association(), advertisement(), PMK,
                                   response_budget=2, eapol_version=1)
        limited.receive(FRAMES[0], .1)
        altered = bytearray(FRAMES[0]); altered[49:81] = b'\x77' * 32
        self.assertIsNotNone(limited.receive(bytes(altered), .2))
        self.assertIsNone(limited.receive(FRAMES[0], .3))
        self.assertEqual(limited.report()['phase'], 'closed')
        self.assertEqual(limited.report()['responses_constructed'], 2)

    def test_new_snonce_requires_new_m3_mic_and_wrapped_key_data(self):
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        ap = bytes.fromhex(AP.replace(':', ''))
        sta = bytes.fromhex(STA.replace(':', ''))
        anonce, old_snonce = FRAMES[0][49:81], FRAMES[1][49:81]
        new_snonce = b'\x55' * 32
        with patch('wifiseclab.protocol.wpa2_session.secrets.token_bytes', return_value=new_snonce):
            m2 = self.session.receive(FRAMES[0], .1)
        self.assertEqual(m2[49:81], new_snonce)
        self.assertIsNone(self.session.receive(FRAMES[2], .2))
        plaintext = unwrap_key_data(FRAMES[2][131:], derive_kek(PMK, ap, sta, anonce, old_snonce))
        modified = bytearray(FRAMES[2])
        modified[131:] = aes_key_wrap(derive_kek(PMK, ap, sta, anonce, new_snonce), plaintext)
        kck = derive_kck(PMK, ap, sta, anonce, new_snonce)
        modified[113:129] = key_mic(modified[32:], kck)
        m4 = self.session.receive(bytes(modified), .3)
        self.assertIsNotNone(m4)
        self.assertEqual(m4[113:129], key_mic(m4[32:], kck))

    def test_m3_retries_use_same_branch_without_installation(self):
        self.session.receive(FRAMES[0], .1)
        self.session.receive(FRAMES[2], .2)
        self.assertIsNone(self.session.receive(FRAMES[2], .3))
        old = int.from_bytes(FRAMES[2][41:49], 'big')
        response = self.session.receive(self.sign_counter(FRAMES[2], old + 1), .4)
        self.assertEqual(decode_key(response, AP, STA)['replay_counter'], old + 1)
        self.assertEqual(self.session.report()['m4_responses_constructed'], 2)
        self.assertFalse(self.session.report()['key_installation_performed'])
        self.assertIsNone(self.session.receive(counter(FRAMES[0], old + 2), .5))

    def test_invalid_mic_does_not_advance_authenticated_counter(self):
        self.session.receive(FRAMES[0], .1)
        damaged = bytearray(counter(FRAMES[2], 500)); damaged[113] ^= 1
        self.assertIsNone(self.session.receive(bytes(damaged), .2))
        self.assertIsNotNone(self.session.receive(FRAMES[2], .3))

    def test_budget_and_timeout_are_terminal_and_clock_is_monotonic(self):
        limited = HandshakeSession(association(), advertisement(), PMK, response_budget=1)
        limited.receive(FRAMES[0], .1)
        self.assertIsNone(limited.receive(FRAMES[2], .2))
        self.assertEqual(limited.report()['phase'], 'closed')
        self.assertFalse(self.session.tick(10))
        self.assertIsNone(self.session.receive(FRAMES[0], 11))
        with self.assertRaises(ValueError):
            self.session.tick(9)

    def test_invalid_clock_permanently_closes_tentative_context(self):
        for invalid in (.05, float('nan'), float('inf'), True, 'invalid'):
            session = HandshakeSession(association(), advertisement(), PMK)
            session.receive(FRAMES[0], .1)
            with self.assertRaises(ValueError):
                session.receive(FRAMES[2], invalid)
            self.assertIsNone(session.receive(FRAMES[2], .2))
            self.assertEqual(session.report()['local_close_reason'], 'invalid_delivery_clock')
            self.assertEqual(session.report()['m4_responses_constructed'], 0)
            json.dumps(session.report(), allow_nan=False)

    def test_missing_m1_unknown_context_and_disconnect_do_not_join(self):
        self.assertIsNone(self.session.receive(FRAMES[2], .1))
        self.session.receive(FRAMES[0], .2)
        unknown = bytearray(FRAMES[1]); unknown[37:39] = b'\x09\x0a'
        self.assertIsNone(self.session.receive(bytes(unknown), .3))
        self.assertIsNone(self.session.receive(FRAMES[2], .4))
        other = HandshakeSession(association(), advertisement(), PMK)
        other.receive(FRAMES[0], .1)
        deauth = bytearray(association()[:24]); deauth[0] = 0xc0; deauth += b'\x03\x00'
        self.assertIsNone(other.receive(bytes(deauth), .2))
        self.assertIsNone(other.receive(FRAMES[2], .3))
