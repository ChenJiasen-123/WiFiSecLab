import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import struct
import unittest
import contextlib
import io
import json
from unittest.mock import MagicMock, patch
import tests.network.test_hotspot as test_hotspot
from tests.network.test_hotspot import AP, STA, SSID, beacon, response, write_pcap
from wifiseclab.network.hotspot import analyze_capture, management, elements
from wifiseclab.core.session import build_association, run_sequence, stage_outcome
from wifiseclab.network.hotspot_cli import main


def profile():
    return dict(ssid=SSID, bssid=AP, capabilities=0x431, group_cipher='000fac04',
                pairwise_ciphers=['000fac04'], akm_suites=['000fac02'],
                supported_rates_hex='82848b960c1218243048606c', pmf_required=False)


class SequenceTests(unittest.TestCase):
    def test_packet_selects_one_suite_and_preserves_identity(self):
        frame = build_association(SSID, AP, STA, profile())
        packet = management(frame)
        self.assertEqual((packet['subtype'], packet['source'], packet['bssid']), (0, STA, AP))
        ies = elements(packet['body'][4:])
        self.assertEqual(ies[0], SSID.encode())
        self.assertEqual(len(ies[1]), 8)
        self.assertEqual(len(ies[50]), 4)
        self.assertEqual(ies[48], bytes.fromhex('0100000fac040100000fac040100000fac020000'))

    def test_incompatible_profile_never_sends(self):
        for changes in ({'pmf_required': True}, {'akm_suites': ['000fac08']},
                        {'supported_rates_hex': 'ff'}, {'capabilities': 0}, {'bssid': STA},
                        {'ssid': 'another network'}, {'ssid': None}, {'identity_conflict': True}):
            called = []
            with self.assertRaises(ValueError):
                run_sequence(SSID, AP, STA, {**profile(), **changes}, lambda *args: called.append(args))
            self.assertEqual(called, [])

    def test_sequence_only_advances_on_unambiguous_observation(self):
        for first, expected in [({}, 1), ({'request_observed': True}, 1),
            ({'request_observed': True, 'correlated_responses': [{'status_code': 13}]}, 1),
            ({'request_observed': True, 'correlated_responses': [{'status_code': 0}, {'status_code': 13}]}, 1),
            ({'request_observed': True, 'correlated_responses': [{'status_code': 0}]}, 2)]:
            calls = []
            def exchange(kind, frame):
                calls.append(frame)
                return first if kind == 'authentication' else {
                    'request_observed': True, 'correlated_responses': [{'status_code': 0, 'aid_valid': True}]}
            result = run_sequence(SSID, AP, STA, profile(), exchange)
            self.assertEqual(len(calls), expected)
            self.assertEqual(result['association_response_confirmed'], expected == 2)
            self.assertFalse(result['key_installation_confirmed'])
            self.assertFalse(result['ap_reset_confirmed'])
            self.assertTrue(all(frame[10:16] == calls[0][10:16] for frame in calls))

    def test_invalid_aid_and_fragment_cannot_prove_success(self):
        self.assertEqual(stage_outcome({'request_observed': True, 'correlated_responses':
            [{'status_code': 0, 'aid_valid': False}]}, 'association'), 'unexpected_invalid_aid')
        for offset, bit in ((1, 4), (22, 1)):
            frame = bytearray(response())
            frame[offset] |= bit
            self.assertIsNone(management(frame))


class AssociationCaptureTests(unittest.TestCase):
    setUp = test_hotspot.HotspotTests.setUp
    def test_response_requires_valid_aid_and_correct_stage(self):
        request = build_association(SSID, AP, STA, profile())
        for aid, expected in ((0xc001, True), (0, False), (0xcfff, False)):
            reply = bytearray(response())
            reply[0] = 0x10
            reply[24:] = struct.pack('<HHH', 0x431, 0, aid)
            write_pcap(self.path, [(0, beacon()), (100, request), (120, bytes(reply))])
            result = analyze_capture(self.path, SSID, AP, request)
            self.assertEqual(result['association_success_response_observed'], expected)
            self.assertFalse(result['authentication_success_response_observed'])

    def test_formal_cli_runs_two_steps_and_stops_after_rejection(self):
        for status in (0, 13):
            output = self.root / str(status)
            adapter, guard = MagicMock(), MagicMock()
            adapter.output_created = True
            adapter.actions = []
            guard.cleanup_errors = []
            advertisement = bytearray(beacon())
            advertisement[34:36] = struct.pack('<H', 0x431)
            advertisement += bytes.fromhex('010482848b96')
            frames = [(0, bytes(advertisement))]
            def enter():
                output.mkdir()
                write_pcap(output / 'air.pcap', frames)
                return adapter
            def send(frame):
                adapter.actions.append(frame)
                millis = len(adapter.actions) * 100
                reply = bytearray(response(status=status if len(adapter.actions) == 1 else 0))
                if len(adapter.actions) == 2:
                    reply[0] = 0x10
                    reply[24:] = struct.pack('<HHH', 0x431, 0, 0xc001)
                frames.extend([(millis, frame), (millis + 20, bytes(reply))])
                write_pcap(output / 'air.pcap', frames)
            adapter.__enter__.side_effect = enter
            adapter.send.side_effect = send
            adapter.report.return_value = {'capture_error': None, 'capture_exit_code': 0, 'cleanup_errors': []}
            with patch('wifiseclab.network.hotspot_cli.sys.platform', 'linux'), \
                 patch('wifiseclab.network.hotspot_cli.os.geteuid', return_value=0, create=True), \
                 patch('wifiseclab.network.hotspot_cli.discover'), \
                 patch('wifiseclab.network.hotspot_cli.RadioRoles.bind'), \
                 patch('wifiseclab.network.hotspot_cli.PhysicalRadioAdapter', return_value=adapter), \
                 patch('wifiseclab.network.hotspot_cli.NetworkGuard', return_value=guard), \
                 patch('wifiseclab.network.hotspot_cli.time.sleep'), contextlib.redirect_stdout(io.StringIO()):
                code = main(['associate', '--ssid', SSID, '--bssid', AP, '--source', STA,
                             '--channel', '10', '--output', str(output)])
            self.assertEqual(code, 0 if status == 0 else 1)
            self.assertEqual(len(adapter.actions), 2 if status == 0 else 1)
            result = json.loads((output / 'hotspot-report.json').read_text(encoding='utf-8'))
            self.assertIn('eapol', result)
            self.assertFalse(result['eapol']['consistent_four_message_path_observed'])
