"""Fail-closed checks for a caller-owned capture and same-host clock relation."""
import time
from wifiseclab.network.handshake_handoff import ClockAnchor


class RuntimeGuard:
    def __init__(self, anchor, producers_alive, *, clock=time.monotonic, realtime=time.time):
        self.anchor = anchor
        self.producers_alive = producers_alive
        self.clock, self.realtime = clock, realtime
        self.failed = False

    def check(self):
        if self.failed:
            raise OSError('Runtime context previously failed')
        try:
            if self.producers_alive() is not True:
                raise OSError('Capture or AP producer is unavailable')
            self.anchor.validate(ClockAnchor.sample(self.clock, self.realtime))
        except (ValueError, OSError) as exc:
            self.failed = True
            raise OSError('Capture/process/clock context unavailable') from exc
