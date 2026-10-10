import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import unittest
from unittest.mock import patch
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES, decode_key
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from wifiseclab.protocol.wpa2 import derive_kck, derive_kek, key_mic, unwrap_key_data
from wifiseclab.protocol.wpa2_session import HandshakeSession
from wifiseclab.network.handshake_runner import run_handshake


class SimulatedAP:
    """In-memory peer: build M3 only after inspecting the generated M2."""
    def __init__(self):
        self.now, self.queue, self.sent = 0., [FRAMES[0]], []
        self.kck, self.simulated_m4_mic_valid = None, False

    def receive(self, timeout):
        self.now += min(timeout, .01) if self.queue else timeout
        return self.queue.pop(0) if self.queue else None

    def submit(self, frame):
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        self.sent.append(frame)
        key = decode_key(frame, AP, STA)
        ap, sta = bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', ''))
        anonce = FRAMES[0][49:81]
        if key['message'] == 2:
            snonce = bytes.fromhex(key['nonce_hex'])
            self.kck = derive_kck(PMK, ap, sta, anonce, snonce)
            if frame[113:129] != key_mic(frame[32:], self.kck):
                raise AssertionError('Generated M2 MIC invalid')
            plaintext = unwrap_key_data(FRAMES[2][131:],
                                       derive_kek(PMK, ap, sta, anonce, FRAMES[1][49:81]))
            m3 = bytearray(FRAMES[2])
            m3[131:] = aes_key_wrap(derive_kek(PMK, ap, sta, anonce, snonce), plaintext)
            m3[113:129] = key_mic(m3[32:], self.kck)
            self.queue.append(bytes(m3))
        elif key['message'] == 4:
            self.simulated_m4_mic_valid = frame[113:129] == key_mic(frame[32:], self.kck)
        return len(frame)


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.ap = SimulatedAP()
        self.session = HandshakeSession(association(), advertisement(), PMK, timeout=1)

    def run_loop(self, **kwargs):
        return run_handshake(self.session, self.ap, lambda: self.ap.now, **kwargs)

    def test_generated_snonce_closed_loop_and_evidence_separation(self):
        result = self.run_loop()
        self.assertEqual([decode_key(f, AP, STA)['message'] for f in self.ap.sent], [2, 4])
        self.assertTrue(self.ap.simulated_m4_mic_valid)
        self.assertEqual(len(result['submissions']), 2)
        self.assertTrue(all(row['submission_complete'] for row in result['submissions']))
        for key in ('over_air_transmission_confirmed', 'ap_authorization_confirmed',
                    'key_installation_confirmed'):
            self.assertFalse(result[key])
        self.assertEqual(result['stop_reason'], 'session_terminal')
        self.assertEqual(result['session']['phase'], 'expired')

    def test_short_unknown_and_exceptional_submission_never_retry(self):
        for outcome in (0, 1, None, True, -1, 10000, OSError('sensitive transport detail')):
            self.setUp()
            def submit(frame):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
            with patch.object(self.ap, 'submit', side_effect=submit) as method:
                result = self.run_loop()
                self.assertEqual(method.call_count, 1)
            self.assertEqual(len(result['submissions']), 1)
            self.assertFalse(result['submissions'][0]['submission_complete'])
            self.assertNotIn('sensitive transport detail', str(result))

    def test_receive_failure_returns_evidence_without_submission(self):
        with patch.object(self.ap, 'receive', side_effect=OSError('private detail')):
            result = self.run_loop()
        self.assertEqual(result['stop_reason'], 'receive_error')
        self.assertEqual(result['submissions'], [])

    def test_receive_returning_after_deadline_cannot_trigger_send(self):
        def late(timeout):
            self.ap.now = 2
            return FRAMES[0]
        with patch.object(self.ap, 'receive', side_effect=late):
            result = self.run_loop()
        self.assertEqual(self.ap.sent, [])
        self.assertEqual(result['session']['responses_constructed'], 0)

    def test_construction_running_past_deadline_cannot_trigger_send(self):
        original = self.session.receive
        def slow(frame, now):
            response = original(frame, now)
            self.ap.now = 2
            return response
        with patch.object(self.session, 'receive', side_effect=slow):
            result = self.run_loop()
        self.assertEqual(result['stop_reason'], 'deadline_before_submission')
        self.assertEqual(result['session']['responses_constructed'], 1)
        self.assertEqual(result['submissions'], [])

    def test_empty_nonadvancing_transport_has_finite_poll_budget(self):
        with patch.object(self.ap, 'receive', return_value=None):
            result = self.run_loop(max_polls=3)
        self.assertEqual(result['polls'], 3)
        self.assertEqual(result['stop_reason'], 'poll_budget_exhausted')
        self.assertEqual(result['submissions'], [])

    def test_transport_failure_and_poll_budget_close_reusable_context(self):
        for failure in ('receive', 'submit', 'invalid_frame', 'poll_budget'):
            self.setUp()
            if failure == 'receive':
                self.ap.receive = lambda timeout: (_ for _ in ()).throw(OSError())
            elif failure == 'submit':
                self.ap.submit = lambda frame: 1
            elif failure == 'invalid_frame':
                self.ap.receive = lambda timeout: bytearray(FRAMES[0])
            else:
                self.ap.receive = lambda timeout: None
            result = self.run_loop(max_polls=3)
            self.assertEqual(result['session']['phase'], 'closed')
            self.assertEqual(result['session']['local_close_reason'], result['stop_reason'])
            self.assertIsNone(self.session.receive(FRAMES[0], .5))

    def test_clock_failure_before_receive_after_receive_and_before_submit(self):
        for values in ((float('nan'),), (0., -.1), (0., .1, .05)):
            self.setUp()
            ticks = iter(values)
            result = run_handshake(self.session, self.ap, lambda: next(ticks))
            self.assertEqual(result['stop_reason'], 'invalid_delivery_clock')
            self.assertEqual(result['session']['phase'], 'closed')
            self.assertEqual(result['submissions'], [])
            self.assertEqual(self.ap.sent, [])
            self.assertIsNone(self.session.receive(FRAMES[0], .5))

    def test_clock_read_failure_closes_session_without_private_error_details(self):
        with patch.object(self.ap, 'receive') as receive:
            def clock():
                raise OSError('private clock detail')
            result = run_handshake(self.session, self.ap, clock)
        receive.assert_not_called()
        self.assertEqual(result['stop_reason'], 'invalid_delivery_clock')
        self.assertEqual(result['session']['phase'], 'closed')
        self.assertNotIn('private clock detail', str(result))
