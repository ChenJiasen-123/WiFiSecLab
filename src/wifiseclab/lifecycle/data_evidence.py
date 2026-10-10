"""Correlate trusted lab endpoint records with a captured PSK handshake.

Hashes bind files, not collector honesty. This is sampled data delivery, not
firmware key installation, continuous authorization, or isolation compliance.
"""
import hashlib
import ipaddress
import json
import math
import re
from wifiseclab.lifecycle.control_snapshot import correlate_snapshot


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def endpoint(value):
    if not isinstance(value, list) or len(value) != 2:
        return False
    try:
        ipaddress.IPv4Address(value[0])
    except (ValueError, TypeError):
        return False
    return type(value[1]) is int and 0 < value[1] < 65536


def correlate_data(report, snapshot, snapshot_metadata, pcap_sha256,
                   client_bytes, server_bytes, metadata, window=10):
    if not finite(window) or not 0 < window <= 30:
        raise ValueError('Expected finite window in (0, 30]')
    if not isinstance(client_bytes, bytes) or not isinstance(server_bytes, bytes):
        raise ValueError('Expected endpoint record bytes')
    reasons = []
    meta = metadata if isinstance(metadata, dict) else {}
    for name, expected in (
        ('source', 'hwsim_endpoint_collector'), ('clock', 'pcap-realtime-same-host'),
        ('bssid', report['bssid']), ('station', report['station']),
        ('pcap_sha256', pcap_sha256),
        ('client_sha256', hashlib.sha256(client_bytes).hexdigest()),
        ('server_sha256', hashlib.sha256(server_bytes).hexdigest())):
        if meta.get(name) != expected or expected is None:
            reasons.append('unbound_' + name)
    for name in ('ap_namespace', 'sta_namespace', 'ap_interface', 'sta_interface'):
        if not isinstance(meta.get(name), str) or not meta[name]:
            reasons.append('missing_' + name)
    if meta.get('ap_namespace') == meta.get('sta_namespace'):
        reasons.append('endpoints_not_isolated')
    control = correlate_snapshot(report, snapshot, snapshot_metadata, pcap_sha256)
    if not control['control_authorized_observed']:
        reasons.append('no_correlated_authorized_snapshot')
    if report.get('rsne_bound_mic_verified_four_message_path_observed') is not True:
        reasons.append('no_rsne_bound_verified_handshake')
    records = []
    for role, raw in (('client', client_bytes), ('server', server_bytes)):
        try:
            record = json.loads(raw) if len(raw) <= 65536 else None
        except (ValueError, UnicodeDecodeError):
            record = None
        if not isinstance(record, dict):
            reasons.append('invalid_' + role + '_record')
            record = {}
        if (record.get('role') != role or record.get('success') is not True
                or record.get('application_payload_verified') is not True):
            reasons.append('unverified_' + role + '_payload')
        records.append(record)
    client, server = records
    token = client.get('token')
    if not isinstance(token, str) or re.fullmatch('[0-9a-f]{32}', token) is None or token != server.get('token'):
        reasons.append('unbound_challenge')
    c_local, c_remote = client.get('local_endpoint'), client.get('remote_endpoint')
    s_local, s_remote = server.get('local_endpoint'), server.get('remote_endpoint')
    if (not all(endpoint(e) for e in (c_local, c_remote, s_local, s_remote))
            or c_local != s_remote or c_remote != s_local
            or c_local[0] != meta.get('station_ipv4') or s_local[0] != meta.get('ap_ipv4')
            or c_local[0] == s_local[0]):
        reasons.append('unbound_endpoint_addresses')
    starts = [x.get('started_at') for x in records]
    ends = [x.get('finished_at') for x in records]
    valid_times = all(finite(t) for t in starts + ends)
    interval = None
    m4_index = control['verified_m4_packet_index']
    m4 = next((e for e in report['events'] if e['packet_index'] == m4_index), None)
    if valid_times:
        interval = {'started_at': min(starts), 'finished_at': max(ends)}
        snapshot_end = (control.get('state_observation_interval') or {}).get('finished_at')
        if (not finite(snapshot_end) or m4 is None or not finite(m4.get('time'))
                or any(a > b for a, b in zip(starts, ends))
                or min(starts) < snapshot_end or max(ends) > m4['time'] + window
                or max(starts) > min(ends)):
            reasons.append('data_outside_session_window')
        if m4 is not None and any(
            e['packet_index'] > m4_index
            and (e.get('observation') or e.get('message') == 1)
            and (not finite(e.get('time')) or e['time'] < m4['time'] or e['time'] <= max(ends))
            for e in report['events']):
            reasons.append('context_changed_before_data_completed')
    else:
        reasons.append('invalid_data_interval')
    return {'correlated': not reasons, 'reasons': reasons,
            'application_round_trip_observed': not reasons,
            'data_observation_interval': interval,
            'handshake_attempt': control['handshake_attempt'],
            'key_installation_confirmed': False, 'isolation_compliance_confirmed': False,
            'scope': 'Trusted same-host collector and endpoint records; sampled normal UDP delivery only.'}
