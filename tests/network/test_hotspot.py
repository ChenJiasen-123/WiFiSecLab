import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from wifiseclab.network.hotspot import analyze_capture, build_request, mac_bytes, rsn_details
from wifiseclab.network.physical import captured_records, management_frame_matches
from wifiseclab.network.hotspot_cli import main

AP = '12:58:e0:93:37:05'
STA = '02:1f:1d:5d:ed:ed'
SSID = 'Test热点'
RSN = bytes.fromhex('0100000fac040100000fac040100000fac028000')


def beacon(ssid=SSID, channel=10):
    name = ssid.encode()
    return (bytes.fromhex('80000000ffffffffffff') + mac_bytes(AP) * 2 + bytes(2)
            + bytes(12) + bytes([0, len(name)]) + name + bytes([3, 1, channel, 48, len(RSN)]) + RSN)


def response(status=0, sequence=0x120, retry=False, destination=STA):
    return (struct.pack('<HH', 0xb0 | (0x800 if retry else 0), 36) + mac_bytes(destination)
            + mac_bytes(AP) * 2 + struct.pack('<HHHH', sequence, 0, 2, status))


def write_pcap(path, frames):
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, 127))
        for millis, frame in frames:
            packet = bytes.fromhex('0000080000000000') + frame
            stream.write(struct.pack('<IIII', 1 + millis // 1000, millis % 1000 * 1000, len(packet), len(packet)))
            stream.write(packet)


class HotspotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'air.pcap'
        self.request = build_request('auth', SSID, AP, STA)

    def test_common_auth_observations_do_not_promote_other_ap_or_sae(self):
        other = mac_bytes('02:00:00:00:00:04')
        wrong = response()[:10] + other + other + response()[22:]
        sae_payload = bytes.fromhex('130001020304')
        sae = response()[:24] + struct.pack('<HHH', 3, 1, 126) + sae_payload
        write_pcap(self.path, [(0, self.request), (10, wrong), (20, sae)])
        report = analyze_capture(self.path, SSID, AP, self.request)
        self.assertFalse(report['response_observed'])
        self.assertFalse(report['authentication_success_response_observed'])
        rows = report['authentication_observations']
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]['source'], '02:00:00:00:00:04')
        self.assertEqual(rows[2]['payload_hex'], sae_payload.hex())
        self.assertEqual(rows[2]['packet_index'], 3)
        self.assertTrue(all(not row['ap_internal_acceptance_confirmed'] for row in rows))

    def test_truncated_auth_observation_survives_without_success(self):
        write_pcap(self.path, [(0, self.request), (10, response()[:26])])
        report = analyze_capture(self.path, SSID, AP, self.request)
        self.assertFalse(report['response_observed'])
        truncated = report['authentication_observations'][1]
        self.assertIn('parse_error', truncated)
        self.assertNotIn('status_code', truncated)
        self.assertEqual(truncated['packet_index'], 2)

    def test_auth_and_probe_construction(self):
        self.assertEqual(len(self.request), 30)
        self.assertEqual(struct.unpack_from('<HHH', self.request, 24), (0, 1, 0))
        probe = build_request('probe', SSID, AP, STA)
        self.assertEqual(probe[0], 0x40)
        self.assertEqual(probe[26:26+len(SSID.encode())], SSID.encode())
        generated = build_request('auth', SSID, AP)
        self.assertEqual(generated[10] & 3, 2)

    def test_ssid_conflicts_are_retained_instead_of_filtered_out(self):
        write_pcap(self.path, [(0, beacon()), (10, beacon(ssid='WrongNet')), (20, beacon())])
        result = analyze_capture(self.path, SSID, AP)
        target = result['targets'][0]
        self.assertTrue(target['identity_conflict'])
        self.assertEqual(target['observed_nonhidden_ssids_hex'], sorted([SSID.encode().hex(), b'WrongNet'.hex()]))

    def test_hidden_beacon_is_not_a_second_network_name(self):
        write_pcap(self.path, [(0, beacon()), (10, beacon(ssid=''))])
        self.assertFalse(analyze_capture(self.path, SSID, AP)['targets'][0]['identity_conflict'])

    def test_advertisement_source_must_match_bssid(self):
        changed = bytearray(beacon()); changed[10] ^= 2
        write_pcap(self.path, [(0, bytes(changed))])
        result = analyze_capture(self.path, SSID, AP)
        self.assertEqual(result['targets'], [])
        self.assertTrue(result['invalid_management'])

    def test_bad_identities_and_ssids_rejected(self):
        for address in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', 'bad', '02:1:22:33:44:55'):
            with self.assertRaises(ValueError):
                build_request('auth', SSID, address)
        for ssid in ('', '汉' * 11):
            with self.assertRaises(ValueError):
                build_request('probe', ssid, AP)
        with self.assertRaises(ValueError):
            build_request('auth', SSID, AP, AP)

    def test_management_match_tolerates_only_selected_rewrites(self):
        changed = bytearray(self.request)
        changed[1] |= 8
        changed[2:4] = b'\x24\x00'
        changed[22:24] = b'\x00\x00'
        self.assertTrue(management_frame_matches(self.request, bytes(changed)))
        self.assertFalse(management_frame_matches(self.request, bytes(changed) + bytes(4)))
        for index in (4, 10, 16, 24, 26, 28):
            wrong = bytearray(changed)
            wrong[index] ^= 1
            self.assertFalse(management_frame_matches(self.request, bytes(wrong)))
        changed[22] |= 1
        self.assertFalse(management_frame_matches(self.request, bytes(changed)))

    def test_auth_response_and_retransmissions(self):
        changed = bytearray(self.request)
        changed[22:24] = bytes(2)
        retry = bytearray(changed)
        retry[1] |= 8
        write_pcap(self.path, [(0, beacon()), (100, bytes(changed)), (101, bytes(retry)),
                               (122, response()), (123, response(retry=True))])
        report = analyze_capture(self.path, SSID, AP, self.request)
        self.assertTrue(report['request_observed'])
        self.assertFalse(report['request_byte_exact_match'])
        self.assertTrue(report['authentication_success_response_observed'])
        self.assertEqual(report['request_retry_frames'], 1)
        self.assertEqual(report['response_retry_frames'], 1)
        self.assertEqual(report['correlated_responses'][0]['delay_ms'], 22)
        self.assertEqual(report['targets'][0]['channel'], 10)
        self.assertTrue(report['targets'][0]['pmf_capable'])

    def test_wrong_recipient_early_and_late_responses_not_correlated(self):
        write_pcap(self.path, [(0, response()), (100, self.request),
                               (120, response(destination='02:11:22:33:44:55')), (5000, response())])
        report = analyze_capture(self.path, SSID, AP, self.request, window=1)
        self.assertFalse(report['response_observed'])

    def test_rejection_is_response_but_not_success(self):
        write_pcap(self.path, [(0, self.request), (20, response(status=13))])
        report = analyze_capture(self.path, SSID, AP, self.request)
        self.assertTrue(report['response_observed'])
        self.assertFalse(report['authentication_success_response_observed'])

    def test_probe_requires_exact_ssid(self):
        probe = build_request('probe', SSID, AP, STA)
        def probe_response(ssid):
            value = bytearray(beacon(ssid))
            value[0] = 0x50
            value[4:10] = mac_bytes(STA)
            return bytes(value)
        write_pcap(self.path, [(0, probe), (10, probe_response('other')), (20, probe_response(SSID))])
        report = analyze_capture(self.path, SSID, AP, probe)
        self.assertEqual(len(report['correlated_responses']), 1)

    def test_live_tail_ignored_but_final_truncation_fails(self):
        write_pcap(self.path, [(0, beacon()), (1, self.request)])
        self.path.write_bytes(self.path.read_bytes()[:-1])
        self.assertEqual(len(list(captured_records(self.path, allow_incomplete=True))), 1)
        with self.assertRaises(ValueError):
            list(captured_records(self.path))

    def test_malformed_rsn_is_not_a_valid_psk_profile(self):
        self.assertIn('rsn_parse_error', rsn_details(b'\x01'))
        self.assertFalse(rsn_details(None)['rsn_present'])

    def test_cli_build_and_offline_analyze(self):
        output = self.root / 'built'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['build', '--kind', 'auth', '--ssid', SSID, '--bssid', AP,
                                   '--source', STA, '--output', str(output)]), 0)
        write_pcap(self.path, [(0, self.request), (20, response())])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['analyze', '--ssid', SSID, '--bssid', AP,
                                   '--pcap', str(self.path), '--request', str(output / 'request.bin')]), 0)

    def test_live_cli_preflight_and_single_submission(self):
        for target_present in (False, True):
            output = self.root / str(target_present)
            adapter = MagicMock()
            adapter.output_created = False
            adapter.actions = []
            adapter.interfaces = {'injector': 'wslabtx', 'listener': 'wslabrx'}
            def enter():
                output.mkdir()
                adapter.output_created = True
                write_pcap(output / 'air.pcap', [(0, beacon(SSID if target_present else 'other'))])
                return adapter
            def send(frame):
                adapter.actions.append({'frame_hex': frame.hex()})
                write_pcap(output / 'air.pcap', [(0, beacon()), (100, frame), (120, response())])
            adapter.__enter__.side_effect = enter
            adapter.send.side_effect = send
            adapter.report.return_value = {'capture_error': None, 'capture_exit_code': 0, 'cleanup_errors': []}
            guard = MagicMock()
            guard.cleanup_errors = []
            with patch('wifiseclab.network.hotspot_cli.sys.platform', 'linux'), \
                 patch('wifiseclab.network.hotspot_cli.os.geteuid', return_value=0, create=True), \
                 patch('wifiseclab.network.hotspot_cli.discover'), \
                 patch('wifiseclab.network.hotspot_cli.RadioRoles.bind'), \
                 patch('wifiseclab.network.hotspot_cli.PhysicalRadioAdapter', return_value=adapter), \
                 patch('wifiseclab.network.hotspot_cli.NetworkGuard', return_value=guard), \
                 patch('wifiseclab.network.hotspot_cli.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
                status = main(['auth', '--ssid', SSID, '--bssid', AP, '--source', STA,
                               '--channel', '10', '--output', str(output)])
            self.assertEqual(status, 0 if target_present else 1)
            self.assertEqual(adapter.send.call_count, int(target_present))
