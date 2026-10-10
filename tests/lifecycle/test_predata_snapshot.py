import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest
import tests.lifecycle.test_control_snapshot as control
from wifiseclab.lifecycle.predata_snapshot import collect_predata_snapshot


class PredataSnapshotTests(unittest.TestCase):
    setUp = control.ControlSnapshotTests.setUp
    analyze = control.ControlSnapshotTests.analyze
    bundle = control.ControlSnapshotTests.bundle

    def collect(self, query, ready=lambda: None):
        report, _, _, digest = self.bundle()
        now = [1.2]
        def sleep(delay):
            now[0] += delay
        return collect_predata_snapshot(query, report, digest, clock=lambda: now[0],
            realtime=lambda: now[0], sleep=sleep, ready=ready, timeout=.1)

    def test_authorized_sample_binds_bytes_and_time(self):
        _, raw, _, digest = self.bundle()
        snapshot, meta = self.collect(lambda remaining: raw)
        self.assertEqual(snapshot, raw)
        self.assertEqual(meta['pcap_sha256'], digest)
        self.assertEqual(meta['finished_at'], 1.2)

    def test_missing_authorization_never_passes(self):
        _, raw, _, _ = self.bundle()
        with self.assertRaises(TimeoutError):
            self.collect(lambda remaining: raw.replace(b'[AUTHORIZED]', b''))

    def test_wrong_station_never_passes(self):
        with self.assertRaises(TimeoutError):
            self.collect(lambda remaining: b'02:00:00:00:00:00\nflags=[AUTH][ASSOC][AUTHORIZED]\n')

    def test_failed_producer_aborts_gate(self):
        def failed():
            raise RuntimeError('producer exited')
        with self.assertRaisesRegex(RuntimeError, 'producer exited'):
            self.collect(lambda remaining: b'', ready=failed)
