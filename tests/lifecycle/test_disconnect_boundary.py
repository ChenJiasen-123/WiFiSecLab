import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import tempfile
from pathlib import Path
import unittest
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES, pcap, analyze_handshake
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from tests.protocol.test_association_gate import response
from wifiseclab.protocol.association_gate import association_evidence
from wifiseclab.protocol.wpa2_session import HandshakeSession


def disconnect(subtype, *, source=None, destination=b'\xff' * 6, bssid=None):
    request = association()
    ap = request[4:10]
    return (bytes([subtype << 4, 0, 0, 0]) + destination + (source or ap) +
            (bssid or ap) + b'\x00\x00\x03\x00')


class DisconnectBoundaryTests(unittest.TestCase):
    def test_ap_broadcast_breaks_passive_path_but_unrelated_frames_do_not(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'air.pcap'
            for subtype in (10, 12):
                cases = [(disconnect(subtype), False),
                         (disconnect(subtype, source=b'\x02\x11\x22\x33\x44\x55'), True),
                         (disconnect(subtype, bssid=b'\x02\x11\x22\x33\x44\x55'), True),
                         (disconnect(subtype, destination=b'\x02\x11\x22\x33\x44\x55'), True)]
                for boundary, expected in cases:
                    pcap(path, [*FRAMES[:2], boundary, *FRAMES[2:]])
                    result = analyze_handshake(path, AP, STA, pmk=PMK)
                    self.assertEqual(result['mic_verified_four_message_path_observed'], expected)
                    self.assertFalse(result['ap_key_installation_confirmed'])

    def test_ap_broadcast_closes_response_controller(self):
        for subtype in (10, 12):
            session = HandshakeSession(association(), advertisement(), PMK)
            session.receive(FRAMES[0], .1)
            self.assertIsNone(session.receive(disconnect(subtype), .2))
            self.assertEqual(session.report()['phase'], 'closed')
            self.assertIsNone(session.receive(FRAMES[2], .3))

    def test_broadcast_after_success_prevents_association_admission(self):
        for subtype in (10, 12):
            result = association_evidence(association(),
                [(.1, association()), (.2, response()), (.3, disconnect(subtype))], now=1)
            self.assertFalse(result['eligible'])
            self.assertIn('management_boundary_after_request', result['reasons'])
