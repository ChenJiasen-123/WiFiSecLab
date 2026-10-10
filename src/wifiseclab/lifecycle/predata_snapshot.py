"""Bounded control-state sampling before the normal WPA2 data exchange."""
import hashlib
import math
from wifiseclab.lifecycle.control_snapshot import correlate_snapshot


def collect_predata_snapshot(query, handshake, capture_digest, *, clock, realtime,
                             sleep, ready, timeout=2):
    """query(remaining) returns raw hostapd STA bytes; all clocks are same host.

    This is a sampled authorization gate, not continuous state or key attestation.
    The final capture hash must be rebound by the collector after capture closes.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
        raise ValueError('Expected finite snapshot timeout in (0, 5]')
    deadline = clock() + timeout
    while True:
        ready()
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError('No correlated authorized AP snapshot before data')
        start = realtime()
        snapshot = query(remaining)
        end = realtime()
        ready()
        if clock() >= deadline:
            raise TimeoutError('AP snapshot exceeded pre-data deadline')
        if not isinstance(snapshot, bytes):
            raise ValueError('Expected raw hostapd control bytes')
        metadata = dict(source='hostapd_ctrl', clock='pcap-realtime-same-host',
                        bssid=handshake['bssid'], station=handshake['station'],
                        snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
                        pcap_sha256=capture_digest, started_at=start, finished_at=end)
        observed = correlate_snapshot(handshake, snapshot, metadata, capture_digest)
        if observed['control_authorized_observed']:
            return snapshot, metadata
        sleep(min(.02, max(0, deadline - clock())))
