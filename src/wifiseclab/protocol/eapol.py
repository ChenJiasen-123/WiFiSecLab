"""Offline WPA2/CCMP EAPOL-Key transcript observations, not internal AP state."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import struct
from ..network.hotspot import mac_bytes, mac_text, management, elements, rsn_details, disconnect_affects_peer
from ..network.hotspot import management_header
from .bip import decode_mme
from ..network.physical import captured_records
from .wpa2 import derive_kck, derive_kek, key_mic, unwrap_key_data
from wifiseclab.protocol.keydata import parse_m3_key_data


class UnsupportedFrame(ValueError):
    def __init__(self, reason, *, eapol_context=False):
        super().__init__(reason)
        self.eapol_context = eapol_context


def decode_key(frame, bssid, station):
    """Decode cleartext infrastructure Data/QoS Data carrying RFC1042 EAPOL.

    Returned message is a flag-pattern classification, not MIC verification.
    No decryption, reassembly or A-MSDU interpretation is attempted.
    """
    ap, sta = mac_bytes(bssid), mac_bytes(station)
    if len(frame) < 24 or frame[0] & 15 != 8:
        return None
    ds = frame[1] & 3
    addresses = (frame[4:10], frame[10:16])
    if ds == 1 and addresses == (ap, sta):
        direction = 'station_to_ap'
    elif ds == 2 and addresses == (sta, ap):
        direction = 'ap_to_station'
    else:
        return None
    if frame[1] & 0x40:
        raise UnsupportedFrame('protected_data_not_decrypted')
    if frame[1] & 4 or frame[22] & 15:
        raise UnsupportedFrame('fragment_not_reassembled')
    if frame[1] & 0x80:
        raise UnsupportedFrame('ordered_data_layout')
    subtype = frame[0] >> 4
    if subtype not in (0, 8):
        return None
    offset = 24
    if subtype == 8:
        if len(frame) < 26:
            raise ValueError('Truncated QoS header')
        if frame[24] & 128:
            raise UnsupportedFrame('amsdu_not_decoded')
        offset += 2
    llc = bytes.fromhex('aaaa03000000888e')
    if frame[offset:offset+8] != llc:
        return None
    raw = frame[offset+8:]
    if len(raw) < 4:
        raise ValueError('Truncated EAPOL header')
    version, kind, size = struct.unpack_from('!BBH', raw)
    if kind != 3:
        return None
    if version not in (1, 2, 3):
        raise UnsupportedFrame('unsupported_eapol_version', eapol_context=True)
    if len(raw) < size + 4 or size < 95:
        raise ValueError('EAPOL-Key declared body truncated or too short')
    # 802.11-2024 12.7.2 Note 2 permits MSDU octets after the PDU.
    # Keep them opaque and outside descriptor parsing and MIC coverage.
    msdu_tail = raw[size + 4:]
    raw = raw[:size + 4]
    body = raw[4:]
    info, key_length = struct.unpack_from('!HH', body, 1)
    if body[0] != 2 or info & 7 != 2:
        raise UnsupportedFrame('requires_rsn_descriptor_2_and_hmac_sha1_mic16', eapol_context=True)
    data_size = struct.unpack_from('!H', body, 93)[0]
    if size != 95 + data_size:
        raise ValueError('Key Data length differs from EAPOL length')
    # The explicit profile avoids guessing SAE/FT/Suite-B or group handshakes.
    message = {0x008a: 1, 0x010a: 2, 0x13ca: 3, 0x030a: 4}.get(info)
    nonce = body[13:45]
    issues = []
    if message and key_length != (16 if message in (1, 3) else 0):
        issues.append('unexpected_key_length_for_ccmp_profile')
    if message and any(body[45:61]):
        issues.append('nonzero_key_iv_for_descriptor_version_2')
    if message in (1, 2, 4) and any(body[61:69]):
        issues.append('nonzero_key_rsc_for_message')
    if message == 1 and any(body[77:93]):
        issues.append('nonzero_m1_mic_storage')
    if message in (1, 2, 3) and nonce == bytes(32):
        issues.append('zero_nonce')
    if message == 4 and (nonce != bytes(32) or data_size):
        issues.append('unexpected_m4_nonce_or_key_data')
    if message and direction != ('ap_to_station' if message in (1, 3) else 'station_to_ap'):
        issues.append('message_direction_mismatch')
    return {'message': message, 'key_info': info, 'key_length': key_length,
            'replay_counter': int.from_bytes(body[5:13], 'big'), 'nonce_hex': nonce.hex(),
            'key_data_length': data_size, 'mic_present': bool(info & 0x100),
            'mic_verified': False, 'direction': direction, 'issues': issues,
            '_eapol': raw,
            'eapol_sha256': hashlib.sha256(raw).hexdigest(),
            'msdu_tail_length': len(msdu_tail),
            'msdu_tail_sha256': hashlib.sha256(msdu_tail).hexdigest() if msdu_tail else None,
            'mac_retry': bool(frame[1] & 8), 'sequence_control': int.from_bytes(frame[22:24], 'little')}


class Transcript:
    """Conservative observation paths. Loss/reordering is never AP misbehavior proof."""
    def __init__(self, pmk=None, ap=None, station=None, unwrap=False):
        self.attempts, self.events, self.anomalies = [], [], []
        self.current = None
        self.pmk, self.ap, self.station = pmk, ap, station
        self.kcks = {}
        self.association_rsne = None
        self.association_evidence = None
        self.unwrap = unwrap
        self.advertisement = None

    def boundary(self, index, reason, timestamp=None):
        self.events.append({'packet_index': index, 'observation': reason, 'time': timestamp})
        self.current = None
        self.association_rsne = None
        self.association_evidence = None
        self.advertisement = None

    def observe(self, packet):
        raw = packet.pop('_eapol')
        packet['mic_valid'] = None
        # This authenticates only the captured M2 payload with the supplied
        # PMK; the observed association frame and AP processing remain unproven.
        packet['m2_rsne_payload_authenticated'] = False
        self.events.append(packet)
        def anomaly(reason):
            self.anomalies.append({'packet_index': packet['packet_index'], 'reason': reason,
                                   'ap_violation_confirmed': False})
            if self.current is not None:
                self.current['ambiguous'] = True
        message, counter, nonce = packet['message'], packet['replay_counter'], packet['nonce_hex']
        if packet['issues']:
            for issue in packet['issues']:
                anomaly(issue)
            return
        if message is None:
            # Group/rekey/request/other flags can change handshake context.
            # Unsupported does not mean malformed or rejected by the AP.
            anomaly('unclassified_eapol_key_context')
            packet['observation'] = 'unsupported_key_info_breaks_observation_path'
            self.current = None
            self.association_rsne = None
            self.association_evidence = None
            return
        if message == 1 and (self.current is None or nonce != self.current['anonce_hex']):
            self.current = {'attempt': len(self.attempts) + 1, 'start_packet_index': packet['packet_index'],
                'anonce_hex': nonce, 'snonce_hex': None, 'm1_counters': [], 'm3_counters': [],
                'snonce_candidates': [], 'm2_branch_counters': {}, 'm3_snonce_contexts': {},
                'association_rsne_hex': self.association_rsne.hex() if self.association_rsne else None,
                'association_evidence': self.association_evidence,
                'm2_rsne_matches_association': None,
                'm3_key_data_unwrap_valid': None,
                'm3_key_data_content_valid': None,
                'advertisement_evidence': self.advertisement,
                'm3_rsne_matches_advertisement': None,
                'observed_path': [], 'ambiguous': False, 'four_messages_observed': False,
                'verified_messages': [],
                'last_reply_counter': None,
                'seen_eapol_hashes': []}
            self.attempts.append(self.current)
        attempt = self.current
        if attempt is None:
            anomaly('missing_m1_context')
            return
        digest = packet['eapol_sha256']
        if digest in attempt['seen_eapol_hashes']:
            packet['observation'] = 'duplicate_eapol_payload'
            return
        attempt['seen_eapol_hashes'].append(digest)
        path = attempt['observed_path']
        if message == 2:
            try:
                ies = elements(raw[99:])
                if 48 not in ies or rsn_details(ies[48]).get('rsn_parse_error'):
                    raise ValueError('Missing or malformed M2 RSNE')
            except ValueError:
                anomaly('missing_or_malformed_m2_rsne')
                return
            expected = attempt['association_rsne_hex']
            packet['rsne_matches_association'] = None if expected is None else ies[48].hex() == expected
            if packet['rsne_matches_association'] is False:
                attempt['m2_rsne_matches_association'] = False
                anomaly('m2_rsne_differs_from_observed_association')
                return
        candidates = self.kcks.setdefault(attempt['attempt'], {})
        selected_snonce = None
        candidate_kck = None
        if self.pmk is not None and message == 2:
            anonce, snonce = bytes.fromhex(attempt['anonce_hex']), bytes.fromhex(nonce)
            candidate_kck = derive_kck(self.pmk, self.ap, self.station, anonce, snonce)
            selected_snonce = nonce
        elif self.pmk is not None and message == 3:
            matches = [sn for sn, kck in candidates.items() if hmac.compare_digest(raw[81:97], key_mic(raw, kck))]
            if len(matches) == 1:
                selected_snonce = matches[0]
                candidate_kck = candidates[selected_snonce]
            elif candidates:
                packet['mic_verified'], packet['mic_valid'] = True, False
                anomaly('mic_verification_failed_for_all_observed_snonce_branches')
                return
        elif self.pmk is not None and message == 4:
            selected_snonce = attempt['m3_snonce_contexts'].get(str(counter))
            candidate_kck = candidates.get(selected_snonce)
        if candidate_kck is not None and message in (2, 3, 4):
            original_mic = raw[81:97]
            packet['mic_verified'] = True
            packet['mic_valid'] = hmac.compare_digest(original_mic, key_mic(raw, candidate_kck))
            if not packet['mic_valid']:
                anomaly('mic_verification_failed_with_supplied_pmk')
                return
            if message == 2:
                packet['m2_rsne_payload_authenticated'] = True
        if message == 1:
            previous_ap_counters = attempt['m1_counters'] + attempt['m3_counters']
            if previous_ap_counters and counter <= max(previous_ap_counters):
                anomaly('nonincreasing_m1_counter')
                return
            attempt['m1_counters'].append(counter)
            if not path:
                path.append(1)
        elif message == 2:
            if counter not in attempt['m1_counters'] or not path or path[-1] not in (1, 2):
                anomaly('m2_without_matching_m1')
                return
            if attempt['last_reply_counter'] is not None and counter <= attempt['last_reply_counter']:
                anomaly('nonincreasing_station_reply_counter')
                return
            if nonce not in attempt['snonce_candidates']:
                attempt['snonce_candidates'].append(nonce)
            attempt['m2_branch_counters'].setdefault(nonce, []).append(counter)
            if candidate_kck is not None:
                candidates[nonce] = candidate_kck
            if packet.get('rsne_matches_association') is True:
                attempt['m2_rsne_matches_association'] = True
            if path[-1] == 1:
                path.append(2)
        elif message == 3:
            if nonce != attempt['anonce_hex'] or path[-1] not in (2, 3, 4):
                anomaly('m3_without_matching_nonce_and_m2')
                return
            # M1 has no MIC: an unrelated high M1 must not poison the
            # authenticated receive history or an earlier M1/M2 branch.
            if selected_snonce is None and len(attempt['snonce_candidates']) == 1:
                selected_snonce = attempt['snonce_candidates'][0]
            branch_counters = attempt['m2_branch_counters'].get(selected_snonce, [])
            if selected_snonce is None:
                branch_counters = [value for values in attempt['m2_branch_counters'].values()
                                   for value in values]
            if not any(value < counter for value in branch_counters):
                anomaly('m3_without_earlier_matching_m2_branch')
                return
            prior = attempt['m3_counters']
            if prior and counter <= max(prior):
                anomaly('nonincreasing_m3_counter')
                return
            if self.unwrap:
                # Only an authenticated, context-matched M3 reaches decryption.
                kek = derive_kek(self.pmk, self.ap, self.station,
                                 bytes.fromhex(nonce), bytes.fromhex(selected_snonce))
                packet['key_data_unwrap_performed'] = True
                try:
                    plaintext = unwrap_key_data(raw[99:], kek)
                except ValueError:
                    packet['key_data_unwrap_valid'] = False
                    attempt['m3_key_data_unwrap_valid'] = False
                    anomaly('m3_key_data_unwrap_integrity_failed')
                    return
                packet['key_data_unwrap_valid'] = True
                packet['unwrapped_key_data_length'] = len(plaintext)
                attempt['m3_key_data_unwrap_valid'] = True
                try:
                    summary = parse_m3_key_data(plaintext)
                except ValueError:
                    packet['key_data_content_valid'] = False
                    attempt['m3_key_data_content_valid'] = False
                    anomaly('m3_key_data_content_invalid')
                    return
                packet['key_data_summary'] = summary
                if not summary['baseline_profile_supported']:
                    anomaly('m3_key_data_profile_unsupported')
                    return
                packet['key_data_content_valid'] = True
                attempt['m3_key_data_content_valid'] = True
                evidence = attempt['advertisement_evidence']
                if evidence is not None:
                    matches = summary['rsne_hex'][0] == evidence['rsne_hex']
                    packet['rsne_matches_advertisement'] = matches
                    attempt['m3_rsne_matches_advertisement'] = matches
                    if not matches:
                        anomaly('m3_rsne_differs_from_observed_advertisement')
                        return
                del plaintext, kek
            attempt['m3_counters'].append(counter)
            if self.pmk is None:
                if len(attempt['snonce_candidates']) != 1:
                    anomaly('multiple_snonce_branches_without_crypto_binding')
                else:
                    selected_snonce = attempt['snonce_candidates'][0]
            attempt['m3_snonce_contexts'][str(counter)] = selected_snonce
            attempt['snonce_hex'] = selected_snonce
            if path[-1] == 2:
                path.append(3)
            else:
                packet['observation'] = 'm3_retransmission_candidate'
        elif message == 4:
            # Some APs track multiple pending M3 counters, not just the latest.
            if counter not in attempt['m3_counters'] or path[-1] not in (3, 4):
                anomaly('m4_without_matching_m3')
                return
            if attempt['last_reply_counter'] is not None and counter <= attempt['last_reply_counter']:
                anomaly('nonincreasing_station_reply_counter')
                return
            if path[-1] == 3:
                path.append(4)
            attempt['four_messages_observed'] = True
        if message in (2, 4):
            attempt['last_reply_counter'] = counter
        if selected_snonce is not None:
            packet['snonce_context'] = selected_snonce
        if packet['mic_valid'] and message not in attempt['verified_messages']:
            attempt['verified_messages'].append(message)

    def report(self):
        return {'attempts': self.attempts, 'events': self.events, 'context_anomalies': self.anomalies,
            'consistent_four_message_path_observed': any(a['four_messages_observed'] and not a['ambiguous']
                                                        for a in self.attempts),
            'mic_verification_performed': any(e.get('mic_verified') for e in self.events),
            'key_data_unwrap_requested': self.unwrap,
            'mic_verified_four_message_path_observed': any(a['four_messages_observed'] and not a['ambiguous']
                and set(a['verified_messages']) == {2, 3, 4} for a in self.attempts),
            'association_bound_mic_verified_four_message_path_observed': any(
                a['four_messages_observed'] and not a['ambiguous'] and set(a['verified_messages']) == {2, 3, 4}
                and a['m2_rsne_matches_association'] is True for a in self.attempts),
            'rsne_bound_mic_verified_four_message_path_observed': any(
                a['four_messages_observed'] and not a['ambiguous'] and set(a['verified_messages']) == {2, 3, 4}
                and a['m2_rsne_matches_association'] is True
                and a['m3_rsne_matches_advertisement'] is True for a in self.attempts),
            'ap_key_installation_confirmed': False,
            'network_identity_validation': {
                'status': 'unknown',
                'pmk_provenance_verified': False,
                'ssid_protection_negotiation_verified': False,
                'authenticated_m3_ssid_binding_verified': False,
                'reason': 'A supplied PMK and matching observed RSNEs do not establish SSID identity; RSNXE SSID protection is outside this baseline profile.'},
            'ap_authorization_confirmed': False, 'key_reinstallation_confirmed': False,
            'limitations': 'Cleartext WPA2 RSN descriptor-version-2 profile only. MIC validation and optional AES Key Wrap verification require a single known PMK; no password guessing. M1 is unauthenticated. M2 RSNE binding and wrap integrity do not prove parsed M3 key-data semantics, AP validation, key installation or authorization. Capture loss, duplication and reordering affect context. Encrypted rekeys and other AKMs require separate support.'}


def analyze_handshake(path, bssid, station, max_gap=30, pmk=None, unwrap=False):
    ap, sta = mac_bytes(bssid), mac_bytes(station)
    if ap == sta or not 0 < max_gap <= 300:
        raise ValueError('Distinct AP/STA and max_gap in (0, 300] required')
    if pmk is not None and (not isinstance(pmk, bytes) or len(pmk) != 32):
        raise ValueError('PMK must be exactly 32 raw bytes')
    if unwrap:
        if pmk is None:
            raise ValueError('Key data unwrap requires a single known PMK')
        try:
            from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        except ImportError as exc:
            raise ValueError('Install wifiseclab[crypto] to unwrap key data') from exc
    trace, quality, rejected, skipped = Transcript(pmk, ap, sta, unwrap), {}, [], {}
    last_time = None
    advertisements, last_record_time = {}, None
    protected_management_observations = []
    group_disconnect_mme_observations = []
    for index, timestamp, frame in captured_records(path, stats=quality):
        if last_record_time is not None and timestamp < last_record_time:
            advertisements.clear()
        last_record_time = timestamp
        advertisements = {key: row for key, row in advertisements.items()
                          if 0 <= timestamp - row['timestamp'] <= max_gap}
        header = management_header(frame)
        if (header and header['protected_bit'] and header['bssid'] == mac_text(ap)
                and header['subtype'] in (10, 12, 13)
                and ((header['source'], header['destination']) in
                     ((mac_text(ap), mac_text(sta)), (mac_text(sta), mac_text(ap)))
                     or header['source'] == mac_text(ap)
                     and header['destination'] == 'ff:ff:ff:ff:ff:ff')):
            protected_management_observations.append({'packet_index': index, 'time': timestamp,
                **header, 'frame_sha256': hashlib.sha256(frame).hexdigest(),
                'body_interpretation': 'unavailable_without_authenticated_decapsulation',
                'peer_acceptance_confirmed': False})
            if header['subtype'] in (10, 12):
                if trace.current is not None:
                    trace.current['ambiguous'] = True
                trace.boundary(index, 'protected_disconnect_header_observed_not_confirmed_reset', timestamp)
        packet = management(frame)
        if (packet and packet['subtype'] in (10, 12)
                and packet['bssid'] == mac_text(ap) and packet['source'] == mac_text(ap)
                and frame[4] & 1):
            row = {'packet_index': index, 'time': timestamp,
                   'subtype': packet['subtype'], 'source_authenticated': False,
                   'frame_sha256': hashlib.sha256(frame).hexdigest(),
                   'receiver_acceptance_confirmed': False}
            try:
                # This baseline accepts only reason code + one final MME.
                # Do not search arbitrary trailing bytes for an IE signature.
                summary = decode_mme(packet['body'][2:])
                if summary['key_type'] != 'IGTK':
                    raise ValueError('Group disconnect requires IGTK context')
                row['mme'] = summary
            except ValueError as exc:
                row['mme_structure_status'] = 'unavailable_or_outside_profile'
                row['reason'] = str(exc)
            group_disconnect_mme_observations.append(row)
        if (packet and packet['source'] == mac_text(ap) and packet['bssid'] == mac_text(ap)
                and ((packet['subtype'] == 8 and packet['destination'] == 'ff:ff:ff:ff:ff:ff')
                     or (packet['subtype'] == 5 and packet['destination'] == mac_text(sta)))):
            rsne = None
            ssid_hex = None
            try:
                if len(packet['body']) < 12:
                    raise ValueError('Truncated advertisement')
                ies = elements(packet['body'][12:])
                if 0 not in ies or len(ies[0]) > 32:
                    raise ValueError('Missing or oversized advertisement SSID')
                ssid_hex = ies[0].hex()
                details = rsn_details(ies.get(48))
                if details.get('rsn_parse_error') or 48 not in ies or 244 in ies:
                    raise ValueError('Unavailable or extended advertisement RSNE')
                rsne = ies[48].hex()
            except ValueError:
                pass  # Keep an unavailable candidate; never silently prefer an earlier valid one.
            advertisements[(rsne, ssid_hex)] = {'packet_index': index, 'timestamp': timestamp,
                'rsne_hex': rsne, 'ssid_hex': ssid_hex, 'subtype': packet['subtype'],
                'source_authenticated': False}
        if packet and frame[10:16] in (ap, sta) and packet['bssid'] == mac_text(ap):
            pair = (frame[4:10], frame[10:16])
            if pair in ((ap, sta), (sta, ap)) or disconnect_affects_peer(packet, mac_text(ap), mac_text(sta)):
                if packet['subtype'] in (0, 2, 10, 12) or (
                    packet['subtype'] == 11 and len(packet['body']) >= 6 and
                    struct.unpack_from('<H', packet['body'], 2)[0] == 1):
                    trace.boundary(index, 'observed_management_boundary_not_confirmed_reset', timestamp)
                    if packet['subtype'] in (0, 2) and pair == (ap, sta):
                        try:
                            fixed = 4 if packet['subtype'] == 0 else 10
                            if len(packet['body']) < fixed:
                                raise ValueError('Truncated association body')
                            ies = elements(packet['body'][fixed:])
                            if 0 not in ies or len(ies[0]) > 32:
                                raise ValueError('Missing or oversized association SSID')
                            details = rsn_details(ies.get(48))
                            if (details.get('rsn_parse_error') or
                                    details.get('akm_suites') != ['000fac02'] or
                                    details.get('pairwise_ciphers') != ['000fac04'] or 244 in ies):
                                raise ValueError('Association is outside the baseline PSK/CCMP context')
                            trace.association_rsne = ies[48]
                            trace.association_evidence = {'packet_index': index, 'timestamp': timestamp,
                                'subtype': packet['subtype'], 'ssid_hex': ies[0].hex(),
                                'source_authenticated': False}
                        except ValueError as exc:
                            trace.events.append({'packet_index': index,
                                'observation': 'association_security_context_unavailable', 'time': timestamp, 'reason': str(exc)})
        try:
            key = decode_key(frame, bssid, station)
        except UnsupportedFrame as exc:
            skipped[str(exc)] = skipped.get(str(exc), 0) + 1
            if exc.eapol_context:
                if trace.current is not None:
                    trace.current['ambiguous'] = True
                trace.boundary(index, 'unsupported_eapol_breaks_observation_path', timestamp)
            continue
        except ValueError as exc:
            rejected.append({'packet_index': index, 'reason': str(exc)})
            trace.boundary(index, 'malformed_eapol_breaks_observation_path', timestamp)
            continue
        if key is None:
            continue
        if last_time is not None and (timestamp < last_time or timestamp - last_time > max_gap):
            trace.boundary(index, 'capture_time_boundary', timestamp)
        if key['message'] == 1 and (trace.current is None or key['nonce_hex'] != trace.current['anonce_hex']):
            trace.advertisement = (next(iter(advertisements.values())).copy()
                                   if len(advertisements) == 1 and
                                   all(row['rsne_hex'] is not None for row in advertisements.values()) else None)
            if trace.advertisement is None:
                key['advertisement_context_status'] = 'missing_stale_conflicting_or_unsupported'
                key['advertisement_candidate_count'] = len(advertisements)
        trace.observe({'packet_index': index, 'time': timestamp, **key})
        last_time = timestamp
    return {'bssid': mac_text(ap), 'station': mac_text(sta), 'capture_quality': quality,
            'protected_management_header_observations': protected_management_observations,
            'group_disconnect_mme_observations': group_disconnect_mme_observations,
            'rejected_frames': rejected, 'unsupported_frames': skipped, **trace.report()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--bssid', required=True)
    parser.add_argument('--station', required=True)
    parser.add_argument('--max-gap', type=float, default=30)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--pmk-file', type=Path, help='Optional single known PMK, 32 raw bytes; never printed')
    parser.add_argument('--unwrap-key-data', action='store_true', help='Verify M3 AES Key Wrap; requires PMK and crypto extra')
    parser.add_argument('--ap-station-file', type=Path, help='Optional hostapd station snapshot')
    parser.add_argument('--snapshot-metadata', type=Path, help='Collector identity, times and file hashes for snapshot')
    args = parser.parse_args(argv)
    try:
        if bool(args.ap_station_file) != bool(args.snapshot_metadata):
            raise ValueError('Provide both --ap-station-file and --snapshot-metadata')
        result = analyze_handshake(args.pcap, args.bssid, args.station, args.max_gap,
                                   args.pmk_file.read_bytes() if args.pmk_file else None, args.unwrap_key_data)
        if args.ap_station_file:
            from ..lifecycle.control_snapshot import correlate_snapshot
            result['ap_control_snapshot'] = correlate_snapshot(result, args.ap_station_file.read_bytes(),
                json.loads(args.snapshot_metadata.read_text(encoding='utf-8')),
                hashlib.sha256(args.pcap.read_bytes()).hexdigest())
        text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(text)
        print(text, end='')
        return 0  # Analysis completed; unknown/observed/anomalous are separate JSON fields.
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
