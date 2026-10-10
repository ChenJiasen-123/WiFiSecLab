"""Bind encrypted capture payloads to trusted lab endpoint records, offline."""
import hashlib
from ..network.ccmp import derive_tk, decrypt_unicast
from ..network.hotspot import mac_bytes
from ..network.physical import captured_records
from wifiseclab.lifecycle.udp_evidence import parse_udp
from wifiseclab.lifecycle.pn_observer import PnObserver


def verify_capture(path, report, pmk, client, server, endpoint_evidence):
    result = {'encrypted_round_trip_observed': False, 'reasons': [], 'matches': [],
              'receiver_replay_protection_confirmed': False,
              'key_installation_confirmed': False,
              'capture_observation_scope': {
                  'timestamp_source': 'pcap_record',
                  'ap_receive_time_confirmed': False,
                  'ap_signal_measurement_available': False,
                  'receiver_acceptance_from_capture_alone': False,
              }}
    if not endpoint_evidence.get('correlated'):
        result['reasons'].append('endpoint_evidence_unbound')
        return result
    attempt = next((a for a in report['attempts'] if a['attempt'] == endpoint_evidence['handshake_attempt']), None)
    if (not attempt or attempt['ambiguous'] or set(attempt['verified_messages']) != {2, 3, 4}
            or not attempt.get('m2_rsne_matches_association')
            or not attempt.get('m3_rsne_matches_advertisement')):
        result['reasons'].append('unsupported_handshake_context')
        return result
    ap, sta = mac_bytes(report['bssid']), mac_bytes(report['station'])
    tk = derive_tk(pmk, ap, sta, bytes.fromhex(attempt['anonce_hex']), bytes.fromhex(attempt['snonce_hex']))
    interval = endpoint_evidence['data_observation_interval']
    token = bytes.fromhex(client['token'])
    previous = None
    quality = {}
    pn_observer = PnObserver()
    for index, timestamp, frame in captured_records(path, stats=quality):
        if index > 100000:
            result['reasons'].append('capture_record_budget_exceeded')
            break
        if previous is not None and timestamp < previous:
            result['reasons'].append('capture_time_regression')
            break
        previous = timestamp
        if not interval['started_at'] <= timestamp <= interval['finished_at']:
            continue
        if (len(frame) < 24 or frame[0] & 15 != 8 or not frame[1] & 64
                or frame[4] & 1 or (frame[4:10], frame[10:16]) not in ((ap, sta), (sta, ap))):
            continue
        try:
            decoded = decrypt_unicast(frame, tk, ap, sta)
            pn_observer.observe(index, frame, decoded)
            udp = parse_udp(decoded['plaintext'])
        except ValueError:
            continue  # Unsupported or damaged frames never become matching evidence.
        uplink = decoded['direction'] == 'uplink'
        prefix = b'WiFiSecLab-request:' if uplink else b'WiFiSecLab-response:'
        source = client['local_endpoint'] if uplink else server['local_endpoint']
        destination = server['local_endpoint'] if uplink else client['local_endpoint']
        if (udp['source'] != source or udp['destination'] != destination
                or udp['payload'] != prefix + token):
            continue
        result['matches'].append({'packet_index': index, 'time': timestamp,
            'direction': decoded['direction'], 'pn': decoded['pn'], 'priority': decoded['priority'],
            'udp_checksum_verified': udp['udp_checksum_verified'],
            'integrity_scope': decoded['integrity_scope'],
            'receiver_acceptance_confirmed': False,
            'frame_sha256': hashlib.sha256(frame).hexdigest()})
    result['pn_observations'] = pn_observer.report()
    if pn_observer.nonce_reuse:
        result['reasons'].append('verified_nonce_reuse_requires_review')
    if pn_observer.incomplete:
        result['reasons'].append('pn_observation_incomplete')
    requests = [e for e in result['matches'] if e['direction'] == 'uplink']
    replies = [e for e in result['matches'] if e['direction'] == 'downlink']
    ordered = any(a['packet_index'] < b['packet_index'] and a['time'] <= b['time']
                  for a in requests for b in replies)
    if not ordered:
        result['reasons'].append('missing_ordered_encrypted_request_response')
    result['capture_quality'] = quality
    result['encrypted_round_trip_observed'] = ordered and not result['reasons']
    return result
