import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
import struct
import unittest
from wifiseclab.protocol.authentication import observe_authentication
from wifiseclab.network.hotspot import management, build_request


class AuthenticationObservationTests(unittest.TestCase):
    def packet(self, body):
        frame = build_request('auth', 'lab', '02:00:00:00:00:01', '02:00:00:00:00:02')
        return management(frame[:24] + body)

    def test_sae_payload_preserved_without_acceptance(self):
        raw = bytes.fromhex('130001020304')
        row = observe_authentication(self.packet(struct.pack('<HHH', 3, 1, 126) + raw))
        self.assertEqual((row['algorithm'], row['transaction'], row['status_code']), (3, 1, 126))
        self.assertEqual(row['payload_hex'], raw.hex())
        self.assertFalse(row['ap_internal_acceptance_confirmed'])
        self.assertFalse(row['peer_completion_confirmed'])
        self.assertEqual(row['payload_validation'], 'not_performed')

    def test_truncation_does_not_fabricate_status(self):
        row = observe_authentication(self.packet(b'\x03\x00'))
        self.assertIn('parse_error', row)
        self.assertNotIn('status_code', row)

    def test_other_management_is_not_authentication(self):
        self.assertIsNone(observe_authentication(None))
        self.assertIsNone(observe_authentication({'subtype': 8}))
