"""Bind a hostapd control snapshot to captured handshake evidence."""
import hashlib
import math
import re


def correlate_snapshot(report, snapshot, metadata, pcap_sha256, window=5):
    """Collector metadata is trusted provenance, not cryptographic attestation.

    A correlated AUTHORIZED flag is a sampled hostapd state, not proof of
    firmware key installation, data delivery, or exact transition timing.
    """
    if (not isinstance(snapshot, bytes) or type(window) not in (int, float)
            or not math.isfinite(window) or not 0 < window <= 30):
        raise ValueError('Expected snapshot bytes and window in (0, 30]')
    reasons = []
    if not isinstance(metadata, dict):
        metadata = {}
    for name, expected in (
            ('source', 'hostapd_ctrl'), ('clock', 'pcap-realtime-same-host'),
            ('bssid', report['bssid']), ('station', report['station']),
            ('snapshot_sha256', hashlib.sha256(snapshot).hexdigest()),
            ('pcap_sha256', pcap_sha256)):
        if metadata.get(name) != expected or expected is None:
            reasons.append('unbound_' + name)
    try:
        lines = snapshot.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        lines = []
    flags = [line[6:] for line in lines[1:] if line.startswith('flags=')]
    if (not lines or lines[0].lower() != report['station'] or len(flags) != 1
            or re.fullmatch(r'(?:\[[A-Za-z0-9_]+\])*', flags[0]) is None):
        reasons.append('invalid_or_wrong_station_snapshot')
        tokens = set()
    else:
        tokens = set(re.findall(r'\[([^]]+)\]', flags[0]))
    start, end = metadata.get('started_at'), metadata.get('finished_at')
    valid_time = all(type(t) in (int, float) and math.isfinite(t) for t in (start, end))
    if not valid_time or start > end:
        reasons.append('invalid_snapshot_interval')
    attempts = report.get('attempts', [])
    attempt = attempts[-1] if attempts else None
    if (attempt is None or attempt['ambiguous'] or not attempt['four_messages_observed']
            or set(attempt['verified_messages']) != {2, 3, 4}):
        reasons.append('no_final_mic_verified_handshake')
        m4 = None
    else:
        replies = [e for e in report['events'] if e.get('message') == 4 and e.get('mic_valid') is True
                   and e['packet_index'] >= attempt['start_packet_index']
                   and e.get('observation') != 'duplicate_eapol_payload']
        m4 = replies[-1] if replies else None
        if m4 is None:
            reasons.append('missing_verified_m4_time')
    if m4 is not None:
        if valid_time and not (m4['time'] <= start <= end <= m4['time'] + window):
            reasons.append('snapshot_outside_post_handshake_window')
        if any(e['packet_index'] > m4['packet_index']
               and (e.get('message') == 1 or
                    e.get('message') is None and e.get('observation')) and (
                   not valid_time or type(e.get('time')) not in (int, float)
                   or not math.isfinite(e['time']) or e['time'] < m4['time']
                   or e['time'] <= end) for e in report['events']):
            reasons.append('later_context_boundary_requires_separate_session_evidence')
    later_boundary = bool(m4 is not None and valid_time and any(
        e['packet_index'] > m4['packet_index']
        and (e.get('message') == 1 or
             e.get('message') is None and e.get('observation'))
        and type(e.get('time')) in (int, float)
        and math.isfinite(e['time']) and e['time'] > end
        for e in report['events']))
    correlated = not reasons
    return {'correlated': correlated, 'reasons': reasons,
            'state_observation_interval': {'started_at': start, 'finished_at': end} if valid_time else None,
            'later_context_boundary_observed': later_boundary,
            'continuous_authorization_confirmed': False,
            'handshake_attempt': attempt['attempt'] if attempt else None,
            'verified_m4_packet_index': m4['packet_index'] if m4 else None,
            'control_authorized_observed': correlated and {'AUTH', 'ASSOC', 'AUTHORIZED'} <= tokens,
            'snapshot_flags': sorted(tokens), 'key_installation_confirmed': False,
            'scope': 'Trusted collector metadata and sampled hostapd control state; no firmware, key identity, data delivery or continuous-state proof.'}
