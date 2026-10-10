import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from wifiseclab.lifecycle.udp_evidence import parse_udp, checksum
from wifiseclab.lifecycle.encrypted_evidence import verify_capture


class UdpEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = json.loads((Path(__file__).resolve().parents[1] / 'fixtures/hwsim-ccmp.json').read_text())
        self.plain = bytes.fromhex(self.f['frames'][0]['plaintext_hex'])

    def test_real_fixture_checksums_and_payload(self):
        parsed = parse_udp(self.plain)
        self.assertTrue(parsed['udp_checksum_verified'])
        self.assertTrue(parsed['payload'].startswith(b'WiFiSecLab-request:'))

    def test_bad_lengths_header_and_udp_checksum_rejected(self):
        for index in (0, 8, 10, 18, len(self.plain) - 1):
            changed = bytearray(self.plain); changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse_udp(bytes(changed))
        with self.assertRaises(ValueError):
            parse_udp(self.plain[:-1])

    def test_fragment_with_correct_header_checksum_rejected(self):
        changed = bytearray(self.plain)
        changed[14:16] = b'\x20\x00'
        changed[18:20] = bytes(2)
        changed[18:20] = checksum(bytes(changed[8:28])).to_bytes(2, 'big')
        with self.assertRaises(ValueError):
            parse_udp(bytes(changed))

    def test_ipv4_zero_udp_checksum_is_explicitly_unverified(self):
        changed = bytearray(self.plain); changed[34:36] = bytes(2)
        self.assertFalse(parse_udp(bytes(changed))['udp_checksum_verified'])

    def capture_bundle(self):
        f = self.f
        request = parse_udp(bytes.fromhex(f['frames'][0]['plaintext_hex']))
        response = parse_udp(bytes.fromhex(f['frames'][1]['plaintext_hex']))
        client = {'token': request['payload'][-16:].hex(), 'local_endpoint': request['source']}
        server = {'local_endpoint': response['source']}
        report = {'bssid': ':'.join(f['ap'][i:i+2] for i in range(0,12,2)),
                  'station': ':'.join(f['station'][i:i+2] for i in range(0,12,2)),
                  'attempts': [{'attempt': 1, 'ambiguous': False, 'verified_messages': [2,3,4],
                                'anonce_hex': f['anonce'], 'snonce_hex': f['snonce'],
                                'm2_rsne_matches_association': True,
                                'm3_rsne_matches_advertisement': True}]}
        evidence = {'correlated': True, 'handshake_attempt': 1,
                    'data_observation_interval': {'started_at': 1, 'finished_at': 2}}
        frames = [(i + 1, 1.2 + i * .1, bytes.fromhex(row['frame_hex'])) for i,row in enumerate(f['frames'])]
        return report, client, server, evidence, frames

    def verify(self, bundle):
        try:
            import cryptography
        except ImportError:
            self.skipTest("Requires optional crypto dependency")
        report, client, server, evidence, frames = bundle
        with patch('wifiseclab.lifecycle.encrypted_evidence.captured_records', return_value=iter(frames)):
            return verify_capture('unused', report, bytes.fromhex(self.f['pmk_hex']), client, server, evidence)

    def test_encrypted_roundtrip_requires_exact_both_directions(self):
        self.assertTrue(self.verify(self.capture_bundle())['encrypted_round_trip_observed'])
        b = self.capture_bundle(); b[1]['token'] = '00' * 16
        self.assertFalse(self.verify(b)['encrypted_round_trip_observed'])
        b = self.capture_bundle(); b[4].pop()
        self.assertFalse(self.verify(b)['encrypted_round_trip_observed'])

    def test_reversed_response_outside_window_and_wrong_peer_fail(self):
        b = self.capture_bundle(); a,z = b[4]; b[4][:] = [(1,1.2,z[2]),(2,1.3,a[2])]
        self.assertFalse(self.verify(b)['encrypted_round_trip_observed'])
        b = self.capture_bundle(); b[3]['data_observation_interval']['finished_at'] = 1.25
        self.assertFalse(self.verify(b)['encrypted_round_trip_observed'])
        b = self.capture_bundle(); b[1]['local_endpoint'] = ['192.0.2.99',51000]
        self.assertFalse(self.verify(b)['encrypted_round_trip_observed'])

    def test_unbound_endpoint_evidence_cannot_be_promoted(self):
        b = self.capture_bundle(); b[3]['correlated'] = False
        self.assertFalse(self.verify(b)['encrypted_round_trip_observed'])
