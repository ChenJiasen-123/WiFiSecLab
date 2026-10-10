import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from wifiseclab.protocol.eapol import decode_key, UnsupportedFrame, analyze_handshake, main

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / 'fixtures/hwsim-wpa2-eapol.json').read_text())
AP, STA = FIXTURE['bssid'], FIXTURE['station']
PMK = bytes.fromhex(FIXTURE['test_pmk_hex'])
FRAMES = [bytes.fromhex(row['frame_hex']) for row in FIXTURE['frames']]


def pcap(path, frames):
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, 127)
    for index, item in enumerate(frames):
        seconds, frame = item if isinstance(item, tuple) else (1, item)
        packet = bytes.fromhex('0000080000000000') + frame
        data += struct.pack('<IIII', seconds, index * 1000, len(packet), len(packet)) + packet
    path.write_bytes(data)


def counter(frame, value):
    frame = bytearray(frame)
    frame[41:49] = value.to_bytes(8, 'big')
    return bytes(frame)


class EapolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'air.pcap'

    def analyze(self, frames=FRAMES, **kwargs):
        pcap(self.path, frames)
        return analyze_handshake(self.path, AP, STA, **kwargs)

    def test_real_hwsim_fixture_mics_and_evidence_limits(self):
        self.assertEqual([decode_key(f, AP, STA)['message'] for f in FRAMES], [1, 2, 3, 4])
        plain = self.analyze()
        self.assertTrue(plain['consistent_four_message_path_observed'])
        self.assertFalse(plain['mic_verification_performed'])
        verified = self.analyze(pmk=PMK)
        self.assertTrue(verified['mic_verified_four_message_path_observed'])
        self.assertEqual(verified['attempts'][0]['verified_messages'], [2, 3, 4])
        for field in ('ap_key_installation_confirmed', 'ap_authorization_confirmed', 'key_reinstallation_confirmed'):
            self.assertFalse(verified[field])
        self.assertNotIn(PMK.hex(), json.dumps(verified))
        self.assertEqual(verified['context_anomalies'], [])

    def test_wrong_pmk_and_modified_payload_never_confirm(self):
        wrong = self.analyze(pmk=bytes(32))
        self.assertFalse(wrong['mic_verified_four_message_path_observed'])
        changed = bytearray(FRAMES[1])
        changed[-1] ^= 1
        result = self.analyze([FRAMES[0], bytes(changed), *FRAMES[2:]], pmk=PMK)
        self.assertFalse(result['consistent_four_message_path_observed'])
        self.assertIn('mic_verification_failed_with_supplied_pmk',
                      [a['reason'] for a in result['context_anomalies']])

    def test_unanswered_high_m1_does_not_poison_earlier_m2_branch(self):
        frames = [*FRAMES[:2], counter(FRAMES[0], 100), *FRAMES[2:]]
        for pmk in (None, PMK):
            result = self.analyze(frames, pmk=pmk)
            self.assertTrue(result['consistent_four_message_path_observed'])
            self.assertEqual(result['context_anomalies'], [])
            if pmk is not None:
                self.assertTrue(result['mic_verified_four_message_path_observed'])

    def test_m3_counter_must_follow_selected_m2_branch(self):
        from wifiseclab.protocol.wpa2 import derive_kck, key_mic
        def signed(frame, value):
            modified = bytearray(counter(frame, value))
            kck = derive_kck(PMK, bytes.fromhex(AP.replace(':', '')),
                             bytes.fromhex(STA.replace(':', '')),
                             FRAMES[0][49:81], FRAMES[1][49:81])
            modified[113:129] = key_mic(modified[32:], kck)
            return bytes(modified)
        result = self.analyze([counter(FRAMES[0], 100), signed(FRAMES[1], 100),
                               FRAMES[2], FRAMES[3]], pmk=PMK)
        self.assertFalse(result['consistent_four_message_path_observed'])
        self.assertIn('m3_without_earlier_matching_m2_branch',
                      [item['reason'] for item in result['context_anomalies']])

    def test_retries_and_nonlatest_m4_are_observations_not_reinstall(self):
        retrans = bytearray(FRAMES[2])
        retrans[1] |= 8
        retrans[22:24] = b'\x10\x12'
        original_counter = decode_key(FRAMES[2], AP, STA)['replay_counter']
        result = self.analyze([*FRAMES[:3], bytes(retrans), counter(FRAMES[2], original_counter + 1), FRAMES[3]])
        self.assertTrue(result['consistent_four_message_path_observed'])
        self.assertEqual(result['attempts'][0]['observed_path'], [1, 2, 3, 4])
        self.assertEqual(result['context_anomalies'], [])
        self.assertEqual(result['events'][3]['observation'], 'duplicate_eapol_payload')
        self.assertFalse(result['key_reinstallation_confirmed'])

    def test_missing_wrong_counter_and_wrong_nonce_do_not_advance(self):
        bad_nonce = bytearray(FRAMES[2])
        bad_nonce[49] ^= 1
        for frames in (FRAMES[1:], [FRAMES[0], counter(FRAMES[1], 999), *FRAMES[2:]],
                       [*FRAMES[:2], bytes(bad_nonce), FRAMES[3]]):
            result = self.analyze(frames)
            self.assertFalse(result['consistent_four_message_path_observed'])
            self.assertTrue(result['context_anomalies'])
            self.assertTrue(all(not a['ap_violation_confirmed'] for a in result['context_anomalies']))

    def test_m4_must_exceed_prior_station_replies_even_if_counter_was_sent(self):
        old = decode_key(FRAMES[2], AP, STA)['replay_counter']
        frames = [*FRAMES[:3], counter(FRAMES[2], old + 1), counter(FRAMES[3], old + 1), FRAMES[3]]
        result = self.analyze(frames)
        self.assertFalse(result['consistent_four_message_path_observed'])
        self.assertIn('nonincreasing_station_reply_counter', [a['reason'] for a in result['context_anomalies']])

    def test_management_and_time_boundaries_prevent_cross_session_join(self):
        assoc = bytes.fromhex('00000000') + bytes.fromhex(AP.replace(':', ''))
        assoc += bytes.fromhex(STA.replace(':', '')) + bytes.fromhex(AP.replace(':', '')) + bytes(6)
        for frames in ([*FRAMES[:3], assoc, FRAMES[3]],
                       [(1, f) for f in FRAMES[:3]] + [(100, FRAMES[3])],
                       [(2, f) for f in FRAMES[:3]] + [(1, FRAMES[3])]):
            result = self.analyze(frames)
            self.assertFalse(result['consistent_four_message_path_observed'])

    def test_qos_and_unsupported_layouts_are_explicit(self):
        qos = bytearray(FRAMES[0])
        qos[0] = 0x88
        qos[24:24] = bytes(2)
        self.assertEqual(decode_key(qos, AP, STA)['message'], 1)
        variants = []
        for offset, mask in ((1, 0x40), (1, 4), (22, 1), (1, 0x80)):
            modified = bytearray(FRAMES[0]); modified[offset] |= mask
            variants.append(modified)
        qos[24] |= 128
        variants.append(qos)
        version = bytearray(FRAMES[0]); version[38] &= ~7
        variants.append(version)
        for frame in variants:
            with self.assertRaises(UnsupportedFrame):
                decode_key(frame, AP, STA)
        stranger = bytearray(FRAMES[0]); stranger[4] ^= 2
        self.assertIsNone(decode_key(stranger, AP, STA))

    def test_declared_lengths_and_direction_cannot_fake_sequence(self):
        for offset in (35, 130):  # EAPOL body length; Key Data length low octet.
            modified = bytearray(FRAMES[0]); modified[offset] ^= 1
            with self.assertRaises(ValueError):
                decode_key(modified, AP, STA)
        swapped = bytearray(FRAMES[0]); swapped[1] = 1
        swapped[4:10], swapped[10:16] = swapped[10:16], swapped[4:10]
        result = self.analyze([bytes(swapped), *FRAMES[1:]])
        self.assertFalse(result['consistent_four_message_path_observed'])
        self.assertEqual(result['events'][0]['issues'], ['message_direction_mismatch'])

    def test_formal_cli_known_pmk_and_no_overwrite(self):
        pcap(self.path, FRAMES)
        pmk_file = Path(self.tmp.name) / 'pmk.bin'; pmk_file.write_bytes(PMK)
        output = Path(self.tmp.name) / 'report.json'
        args = ['--pcap', str(self.path), '--bssid', AP, '--station', STA,
                '--pmk-file', str(pmk_file), '--output', str(output)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 0)
        self.assertTrue(json.loads(output.read_text())['mic_verified_four_message_path_observed'])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(args)

    def test_profile_fields_reject_even_when_mic_is_valid(self):
        from wifiseclab.protocol.wpa2 import derive_kck, key_mic
        kck = derive_kck(PMK, bytes.fromhex(AP.replace(':', '')), bytes.fromhex(STA.replace(':', '')),
                         FRAMES[0][49:81], FRAMES[1][49:81])
        for index, offset, reason in (
                (0, 40, 'unexpected_key_length_for_ccmp_profile'),
                (1, 40, 'unexpected_key_length_for_ccmp_profile'),
                (2, 40, 'unexpected_key_length_for_ccmp_profile'),
                (3, 40, 'unexpected_key_length_for_ccmp_profile'),
                (2, 81, 'nonzero_key_iv_for_descriptor_version_2'),
                (1, 97, 'nonzero_key_rsc_for_message'),
                (3, 97, 'nonzero_key_rsc_for_message'),
                (0, 113, 'nonzero_m1_mic_storage')):
            with self.subTest(index=index, field=reason):
                modified = bytearray(FRAMES[index]); modified[offset] ^= 1
                if index:
                    modified[113:129] = key_mic(modified[32:], kck)
                frames = list(FRAMES); frames[index] = bytes(modified)
                result = self.analyze(frames, pmk=PMK)
                self.assertFalse(result['consistent_four_message_path_observed'])
                self.assertIn(reason, [a['reason'] for a in result['context_anomalies']])
        # M3 conveys the starting GTK PN/TSC; a nonzero RSC is legitimate.
        m3 = bytearray(FRAMES[2]); m3[97] = 7
        m3[113:129] = key_mic(m3[32:], kck)
        self.assertTrue(self.analyze([*FRAMES[:2], bytes(m3), FRAMES[3]], pmk=PMK)
                        ['mic_verified_four_message_path_observed'])

    def test_unclassified_key_cannot_bridge_handshake_context(self):
        for flags in (0x090a, 0x0302, 0x050a):  # Request, group, Error: not supported here.
            altered = bytearray(FRAMES[1])
            altered[37:39] = flags.to_bytes(2, 'big')
            result = self.analyze([*FRAMES[:2], bytes(altered), *FRAMES[2:]], pmk=PMK)
            self.assertFalse(result['mic_verified_four_message_path_observed'])
            self.assertIn('unclassified_eapol_key_context',
                          [a['reason'] for a in result['context_anomalies']])
            self.assertTrue(all(not a['ap_violation_confirmed'] for a in result['context_anomalies']))
        # A later independently complete exchange can establish its own path.
        recovered = self.analyze([*FRAMES[:2], bytes(altered), *FRAMES], pmk=PMK)
        self.assertTrue(recovered['mic_verified_four_message_path_observed'])
        self.assertEqual(len(recovered['attempts']), 2)

    def test_m2_rsne_binds_to_observed_association_not_just_mic(self):
        from tests.protocol.test_wpa2 import association
        assoc = association()
        bound = self.analyze([assoc, *FRAMES], pmk=PMK)
        self.assertTrue(bound['association_bound_mic_verified_four_message_path_observed'])
        unbound = self.analyze(pmk=PMK)
        self.assertTrue(unbound['mic_verified_four_message_path_observed'])
        self.assertFalse(unbound['association_bound_mic_verified_four_message_path_observed'])
        self.assertIsNone(unbound['attempts'][0]['m2_rsne_matches_association'])
        # Both RSNEs are well formed; a capability difference still violates bitwise binding.
        changed = bytearray(assoc); changed[-2] ^= 1
        mismatch = self.analyze([bytes(changed), *FRAMES], pmk=PMK)
        self.assertFalse(mismatch['consistent_four_message_path_observed'])
        self.assertIn('m2_rsne_differs_from_observed_association',
                      [a['reason'] for a in mismatch['context_anomalies']])
        # An intervening deauthentication cannot leave old association context attached.
        deauth = bytearray(assoc[:24]); deauth[0] = 0xc0; deauth += b'\x03\x00'
        after_boundary = self.analyze([assoc, bytes(deauth), *FRAMES], pmk=PMK)
        self.assertFalse(after_boundary['association_bound_mic_verified_four_message_path_observed'])

    def test_missing_or_duplicate_m2_rsne_is_not_a_consistent_path(self):
        for replacement in (bytes([49]) + FRAMES[1][132:],
                            FRAMES[1][131:] * 2):
            changed = bytearray(FRAMES[1][:131] + replacement)
            changed[34:36] = (len(changed) - 36).to_bytes(2, 'big')
            changed[129:131] = len(replacement).to_bytes(2, 'big')
            result = self.analyze([FRAMES[0], bytes(changed), *FRAMES[2:]])
            self.assertFalse(result['consistent_four_message_path_observed'])
            self.assertIn('missing_or_malformed_m2_rsne',
                          [a['reason'] for a in result['context_anomalies']])

    def test_unsupported_eapol_profile_breaks_but_unrelated_data_does_not(self):
        for offset, value in ((32, 9), (36, 254), (38, 9)):
            altered = bytearray(FRAMES[1]); altered[offset] = value
            result = self.analyze([*FRAMES[:2], bytes(altered), *FRAMES[2:]], pmk=PMK)
            self.assertFalse(result['mic_verified_four_message_path_observed'])
            self.assertIn('unsupported_eapol_breaks_observation_path',
                          [e.get('observation') for e in result['events']])
        unrelated = bytearray(FRAMES[1]); unrelated[30:32] = b'\x08\x00'
        result = self.analyze([*FRAMES[:2], bytes(unrelated), *FRAMES[2:]], pmk=PMK)
        self.assertTrue(result['mic_verified_four_message_path_observed'])
