import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import hashlib
import json
import unittest
from pathlib import Path
import tests.protocol.test_eapol as golden
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES
from wifiseclab.lifecycle.control_snapshot import correlate_snapshot
from wifiseclab.protocol.eapol import main
import contextlib
import io


class ControlSnapshotTests(unittest.TestCase):
    setUp = golden.EapolTests.setUp
    analyze = golden.EapolTests.analyze

    def bundle(self):
        report = self.analyze(pmk=PMK)
        snapshot = (STA + '\nflags=[AUTH][ASSOC][AUTHORIZED]\n').encode()
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        metadata = {'source': 'hostapd_ctrl', 'clock': 'pcap-realtime-same-host',
                    'bssid': AP, 'station': STA, 'snapshot_sha256': hashlib.sha256(snapshot).hexdigest(),
                    'pcap_sha256': digest, 'started_at': 1.1, 'finished_at': 1.2}
        return report, snapshot, metadata, digest

    def test_correlated_control_state_does_not_claim_key_installation(self):
        result = correlate_snapshot(*self.bundle())
        self.assertTrue(result['control_authorized_observed'])
        self.assertFalse(result['key_installation_confirmed'])
        self.assertFalse(result['continuous_authorization_confirmed'])
        self.assertFalse(result['later_context_boundary_observed'])
        self.assertEqual(result['state_observation_interval'],
                         {'started_at': 1.1, 'finished_at': 1.2})

    def test_missing_provenance_and_wrong_hash_or_peer_remain_unbound(self):
        report, snapshot, meta, digest = self.bundle()
        for field in ('source', 'clock', 'bssid', 'station', 'pcap_sha256', 'snapshot_sha256'):
            changed = dict(meta); changed[field] = 'wrong'
            self.assertFalse(correlate_snapshot(report, snapshot, changed, digest)['correlated'])
        self.assertFalse(correlate_snapshot(report, snapshot, {}, digest)['correlated'])

    def test_invalid_old_future_or_cross_clock_times(self):
        report, snapshot, meta, digest = self.bundle()
        for start, end in ((0, .5), (10, 11), (2, 1), (float('nan'), 2), (True, 2)):
            changed = dict(meta, started_at=start, finished_at=end)
            self.assertFalse(correlate_snapshot(report, snapshot, changed, digest)['correlated'])

    def test_duplicate_flags_and_other_station_cannot_confirm(self):
        report, snapshot, meta, digest = self.bundle()
        for changed in (snapshot + b'flags=[AUTHORIZED]\n', snapshot.replace(STA.encode(), AP.encode()),
                        snapshot.replace(b'[AUTHORIZED]', b'[AUTHORIZED')):
            metadata = dict(meta, snapshot_sha256=hashlib.sha256(changed).hexdigest())
            self.assertFalse(correlate_snapshot(report, changed, metadata, digest)['correlated'])

    def test_control_not_authorized_and_later_boundary(self):
        report, snapshot, meta, digest = self.bundle()
        changed = snapshot.replace(b'[AUTHORIZED]', b'')
        metadata = dict(meta, snapshot_sha256=hashlib.sha256(changed).hexdigest())
        result = correlate_snapshot(report, changed, metadata, digest)
        self.assertTrue(result['correlated'])
        self.assertFalse(result['control_authorized_observed'])
        report['events'].append({'packet_index': 5, 'observation': 'observed_management_boundary_not_confirmed_reset'})
        self.assertFalse(correlate_snapshot(report, snapshot, meta, digest)['correlated'])

    def test_boundary_time_is_scoped_to_snapshot_end(self):
        for timestamp, expected in ((1.15, False), (1.2, False), (1.21, True),
                                    (None, False), (float('nan'), False),
                                    (True, False), (0, False)):
            with self.subTest(timestamp=timestamp):
                report, snapshot, meta, digest = self.bundle()
                report['events'].append({'packet_index': 5, 'time': timestamp,
                    'observation': 'observed_management_boundary_not_confirmed_reset'})
                result = correlate_snapshot(report, snapshot, meta, digest)
                self.assertEqual(result['control_authorized_observed'], expected)
                self.assertEqual(result['later_context_boundary_observed'], expected)

    def test_m1_before_snapshot_end_breaks_session_binding(self):
        for timestamp, expected in ((1.05, False), (1.15, False), (1.2, False),
                                    (1.21, True), (None, False),
                                    (float('nan'), False), (True, False), (0, False)):
            with self.subTest(timestamp=timestamp):
                report, snapshot, meta, digest = self.bundle()
                report['events'].append({'packet_index': 5, 'time': timestamp,
                                         'message': 1, 'mic_valid': None})
                result = correlate_snapshot(report, snapshot, meta, digest)
                self.assertEqual(result['control_authorized_observed'], expected)
                self.assertEqual(result['later_context_boundary_observed'], expected)
                self.assertFalse(result['continuous_authorization_confirmed'])
                self.assertFalse(result['key_installation_confirmed'])

    def test_snapshot_window_rejects_nonfinite_and_boolean_values(self):
        for window in (True, False, float('nan'), float('inf'), '5', None, 0, 31):
            with self.subTest(window=window), self.assertRaises(ValueError):
                correlate_snapshot(*self.bundle(), window=window)

    def test_cli_snapshot_pair_is_integrated(self):
        report, snapshot, meta, digest = self.bundle()
        root = Path(self.tmp.name)
        (root / 'ap.txt').write_bytes(snapshot)
        (root / 'meta.json').write_text(json.dumps(meta))
        (root / 'pmk').write_bytes(PMK)
        args = ['--pcap', str(self.path), '--bssid', AP, '--station', STA,
                '--pmk-file', str(root / 'pmk'), '--ap-station-file', str(root / 'ap.txt')]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(args)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args + ['--snapshot-metadata', str(root / 'meta.json')]), 0)
        self.assertTrue(json.loads(output.getvalue())['ap_control_snapshot']['control_authorized_observed'])
