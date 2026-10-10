import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import copy
import hashlib
import json
import unittest
import tests.lifecycle.test_control_snapshot as control_tests
from wifiseclab.lifecycle.data_evidence import correlate_data


class DataEvidenceTests(unittest.TestCase):
    setUp = control_tests.ControlSnapshotTests.setUp
    analyze = control_tests.ControlSnapshotTests.analyze
    bundle = control_tests.ControlSnapshotTests.bundle

    def data_bundle(self):
        report, snapshot, snapshot_meta, digest = self.bundle()
        report['rsne_bound_mic_verified_four_message_path_observed'] = True
        client = {'role': 'client', 'success': True, 'application_payload_verified': True,
                  'token': '11' * 16, 'started_at': 1.4, 'finished_at': 1.6,
                  'local_endpoint': ['192.0.2.2', 51000],
                  'remote_endpoint': ['192.0.2.1', 49321]}
        server = dict(client, role='server', started_at=1.3, finished_at=1.5,
                      local_endpoint=client['remote_endpoint'], remote_endpoint=client['local_endpoint'])
        meta = {'source': 'hwsim_endpoint_collector', 'clock': 'pcap-realtime-same-host',
                'bssid': report['bssid'], 'station': report['station'], 'pcap_sha256': digest,
                'ap_namespace': 'ap', 'sta_namespace': 'sta', 'ap_interface': 'wlan2',
                'sta_interface': 'wlan3', 'ap_ipv4': '192.0.2.1', 'station_ipv4': '192.0.2.2'}
        return report, snapshot, snapshot_meta, digest, client, server, meta

    def check(self, bundle):
        report, snapshot, snapshot_meta, digest, client, server, meta = bundle
        c = json.dumps(client).encode(); s = json.dumps(server).encode()
        meta = dict(meta, client_sha256=hashlib.sha256(c).hexdigest(), server_sha256=hashlib.sha256(s).hexdigest())
        return correlate_data(report, snapshot, snapshot_meta, digest, c, s, meta)

    def test_valid_sample_does_not_claim_internal_state_or_isolation(self):
        result = self.check(self.data_bundle())
        self.assertTrue(result['application_round_trip_observed'])
        self.assertFalse(result['key_installation_confirmed'])
        self.assertFalse(result['isolation_compliance_confirmed'])

    def test_different_run_identity_payload_peer_and_times_rejected(self):
        for target, field, value in (
                (6, 'station', 'wrong'), (6, 'pcap_sha256', 'wrong'),
                (6, 'source', 'other'), (6, 'sta_namespace', 'ap'),
                (4, 'token', '22' * 16), (4, 'success', 1),
                (5, 'remote_endpoint', ['192.0.2.9', 51000]),
                (4, 'started_at', 1.1), (4, 'finished_at', 40),
                (5, 'finished_at', float('nan')), (4, 'started_at', True)):
            with self.subTest(field=field, value=value):
                bundle = self.data_bundle(); bundle[target][field] = value
                self.assertFalse(self.check(bundle)['correlated'])

    def test_boundary_before_data_end_blocks_but_later_cleanup_does_not(self):
        for timestamp, expected in ((1.45, False), (1.6, False), (1.61, True), (None, False)):
            bundle = self.data_bundle()
            bundle[0]['events'].append({'packet_index': 5, 'time': timestamp, 'observation': 'boundary'})
            self.assertEqual(self.check(bundle)['correlated'], expected)

    def test_new_handshake_during_data_requires_separate_context(self):
        bundle = self.data_bundle()
        bundle[0]['events'].append({'packet_index': 5, 'time': 1.5, 'message': 1})
        self.assertIn('context_changed_before_data_completed', self.check(bundle)['reasons'])

    def test_tampered_bytes_fail_hash_binding(self):
        b = self.data_bundle(); c = json.dumps(b[4]).encode(); s = json.dumps(b[5]).encode()
        meta = dict(b[6], client_sha256=hashlib.sha256(c).hexdigest(), server_sha256=hashlib.sha256(s).hexdigest())
        result = correlate_data(*b[:4], c + b' ', s, meta)
        self.assertIn('unbound_client_sha256', result['reasons'])


    def test_m1_during_control_query_blocks_authorization_and_data_binding(self):
        bundle = self.data_bundle()
        bundle[0]['events'].append({'packet_index': 5, 'time': 1.15, 'message': 1})
        result = self.check(bundle)
        self.assertIn('no_correlated_authorized_snapshot', result['reasons'])
        self.assertFalse(result['application_round_trip_observed'])
        self.assertFalse(result['key_installation_confirmed'])
