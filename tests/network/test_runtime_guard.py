import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest
from wifiseclab.network.handshake_handoff import ClockAnchor
from wifiseclab.network.runtime_guard import RuntimeGuard


class RuntimeGuardTests(unittest.TestCase):
    def test_stable_clocks_and_live_producer(self):
        guard=RuntimeGuard(ClockAnchor(100,10,0),lambda:True,clock=lambda:11,realtime=lambda:101)
        guard.check()
        self.assertFalse(guard.failed)

    def test_producer_exit_poisoning_survives_later_recovery(self):
        alive=[False]
        guard=RuntimeGuard(ClockAnchor(100,10,0),lambda:alive[0],clock=lambda:11,realtime=lambda:101)
        with self.assertRaises(OSError):guard.check()
        alive[0]=True
        with self.assertRaises(OSError):guard.check()

    def test_wall_jump_or_monotonic_reversal_closes_context(self):
        for wall,mono in ((120,11),(99,9)):
            guard=RuntimeGuard(ClockAnchor(100,10,0),lambda:True,clock=lambda:mono,realtime=lambda:wall)
            with self.assertRaises(OSError):guard.check()
            self.assertTrue(guard.failed)

    def test_probe_io_failure_closes_context(self):
        def failed():raise OSError('producer handle unavailable')
        guard=RuntimeGuard(ClockAnchor(100,10,0),failed,clock=lambda:11,realtime=lambda:101)
        with self.assertRaises(OSError):guard.check()
        self.assertTrue(guard.failed)
