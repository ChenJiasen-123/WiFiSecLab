"""Same-host capture/monotonic clock binding and association-to-EAPOL handoff."""
from dataclasses import dataclass
import math
import time
import tempfile
from pathlib import Path
from ..protocol.association_gate import admitted_session
from wifiseclab.network.physical import captured_records
from wifiseclab.network.radio_handshake import PhysicalHandshakeTransport


@dataclass(frozen=True)
class ClockAnchor:
    realtime: float
    monotonic: float
    uncertainty: float

    def __post_init__(self):
        if (any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
                for value in (self.realtime, self.monotonic, self.uncertainty)) or self.uncertainty > .025):
            raise ValueError('Invalid clock anchor')

    @classmethod
    def sample(cls, clock=time.monotonic, realtime=time.time):
        before, wall, after = clock(), realtime(), clock()
        if (any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
                for value in (before, wall, after)) or not 0 <= after - before <= .05):
            raise ValueError('Clock anchor sampling interval is invalid or too wide')
        return cls(wall, (before + after) / 2, (after - before) / 2)

    def validate(self, current):
        if (current.monotonic < self.monotonic or
                abs((current.realtime - self.realtime) -
                    (current.monotonic - self.monotonic)) > .05 + self.uncertainty + current.uncertainty):
            raise ValueError('Capture realtime/monotonic clock relationship changed')

    def convert(self, timestamp):
        return self.monotonic + timestamp - self.realtime


def prepare_handoff(adapter, association, advertisement, pmk, anchor, *,
                    clock=time.monotonic, realtime=time.time, sleep=time.sleep,
                    window=2, **session_options):
    """Capture must be local to these clocks; caller anchors before association.

    Return admitted session and owned-reader transport. No frames are submitted.
    Pending EAPOL records stay in the file for the transport to consume later.
    """
    if not adapter.active or adapter.capture is None or adapter.capture.poll() is not None:
        raise OSError('Independent capture producer is unavailable')
    if type(window) not in (int, float) or not math.isfinite(window) or not 0 < window <= 10:
        raise ValueError('Invalid admission window')
    start = ClockAnchor.sample(clock, realtime)
    anchor.validate(start)
    path = adapter.output / 'air.pcap'
    snapshot_size = path.stat().st_size
    if snapshot_size > 32 * 1024 * 1024:
        raise ValueError('Capture exceeds bounded handoff snapshot size')
    quality, records = {}, []
    with path.open('rb') as stream:
        data = stream.read(snapshot_size)
    if len(data) != snapshot_size:
        raise ValueError('Capture shrank during handoff snapshot')
    with tempfile.TemporaryDirectory(prefix='wslab-handoff-') as directory:
        snapshot = Path(directory) / 'snapshot.pcap'
        snapshot.write_bytes(data)
        for index, timestamp, frame in captured_records(snapshot, allow_incomplete=True, stats=quality):
            if timestamp >= start.realtime - window:
                records.append((index, timestamp, frame))
                if len(records) > 4096:
                    raise ValueError('Capture exceeds admission record budget')
    end = ClockAnchor.sample(clock, realtime)
    anchor.validate(end)
    session = admitted_session(association, advertisement, pmk,
        [(anchor.convert(timestamp), frame) for _, timestamp, frame in records],
        now=end.monotonic, window=window, **session_options)
    evidence = session.admission_evidence
    for row in evidence['requests'] + evidence['responses']:
        index, timestamp, _ = records[row['record_index']]
        row.update(capture_packet_index=index, capture_time=timestamp)
    first = evidence['responses'][0]
    evidence['clock_binding'] = {'source': 'caller_declared_same_host_realtime_capture',
        'anchor_realtime': anchor.realtime, 'anchor_monotonic': anchor.monotonic,
        'anchor_uncertainty': anchor.uncertainty, 'checked_at_monotonic': end.monotonic,
        'independently_attested': False}
    evidence['capture_quality_at_handoff'] = quality
    transport = PhysicalHandshakeTransport(adapter, session, not_before=first['capture_time'],
        after_record_index=first['capture_packet_index'], clock=clock, sleep=sleep,
        clock_guard=lambda: anchor.validate(ClockAnchor.sample(clock, realtime)))
    return session, transport
