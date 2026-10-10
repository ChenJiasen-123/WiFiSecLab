import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import json
import unittest
from pathlib import Path
from wifiseclab.network.ccmp import derive_tk, decrypt_unicast
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError:
    AESCCM = None


@unittest.skipIf(AESCCM is None, 'Requires optional crypto dependency')
class CcmpTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((Path(__file__).resolve().parents[1] / 'fixtures/hwsim-ccmp.json').read_text())
        f = self.fixture
        self.ap, self.sta = bytes.fromhex(f['ap']), bytes.fromhex(f['station'])
        self.tk = derive_tk(bytes.fromhex(f['pmk_hex']), self.ap, self.sta,
                            bytes.fromhex(f['anonce']), bytes.fromhex(f['snonce']))
        self.frame = bytes.fromhex(f['frames'][0]['frame_hex'])

    def decrypt(self, frame, tk=None):
        return decrypt_unicast(frame, self.tk if tk is None else tk, self.ap, self.sta)

    def test_real_hwsim_udp_both_directions(self):
        directions = set()
        for row in self.fixture['frames']:
            result = self.decrypt(bytes.fromhex(row['frame_hex']))
            self.assertEqual(result['plaintext'], bytes.fromhex(row['plaintext_hex']))
            self.assertIn(b'WiFiSecLab-', result['plaintext'])
            self.assertFalse(result['receiver_acceptance_confirmed'])
            directions.add(result['direction'])
        self.assertEqual(directions, {'uplink', 'downlink'})

    def test_authenticated_fields_ciphertext_tag_and_key_mutation_fail(self):
        for index in (16, 24, 32, len(self.frame) - 1):
            changed = bytearray(self.frame); changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.decrypt(bytes(changed))
        with self.assertRaises(ValueError):
            self.decrypt(self.frame, bytes(16))

    def test_masked_retry_duration_sequence_remain_decryptable(self):
        changed = bytearray(self.frame)
        changed[1] ^= 56  # Retry, Power Management, More Data
        changed[2:4] = b'\xff\xff'
        changed[22] ^= 240; changed[23] ^= 255
        self.assertEqual(self.decrypt(bytes(changed))['plaintext'], self.decrypt(self.frame)['plaintext'])

    def test_unsupported_context_never_guessed(self):
        for index, mask in ((1, 128), (1, 4), (22, 1), (27, 64), (26, 1)):
            changed = bytearray(self.frame); changed[index] ^= mask
            with self.subTest(index=index, mask=mask), self.assertRaises(ValueError):
                self.decrypt(bytes(changed))
        with self.assertRaises(ValueError):
            self.decrypt(self.frame[:30])

    def test_qos_tid_is_authenticated_and_amsdu_is_rejected(self):
        frame = bytearray(self.frame[:24])
        frame[0] = 136
        header = self.frame[24:32]
        pn = header[:2] + header[4:8]
        aad = bytes([136, frame[1] & 199]) + bytes(frame[4:22]) + bytes(2) + bytes([5, 0])
        nonce = bytes([5]) + bytes(frame[10:16]) + pn[::-1]
        plaintext = b'bounded QoS test'
        encrypted = AESCCM(self.tk, tag_length=8).encrypt(nonce, plaintext, aad)
        packet = bytes(frame) + bytes([5, 0]) + header + encrypted
        self.assertEqual(self.decrypt(packet)['plaintext'], plaintext)
        changed = bytearray(packet); changed[24] ^= 1
        with self.assertRaises(ValueError):
            self.decrypt(bytes(changed))
        changed[24] |= 128
        with self.assertRaises(ValueError):
            self.decrypt(bytes(changed))
