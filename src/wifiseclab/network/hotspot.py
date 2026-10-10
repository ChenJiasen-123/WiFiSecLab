"""Dependency-free hotspot frame construction and capture evidence analysis."""
import re
import secrets
import struct
from wifiseclab.network.physical import captured_records, management_frame_matches
from ..protocol.authentication import observe_authentication


def mac_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Expected a colon-separated MAC address')
    raw = bytes.fromhex(value.replace(':', ''))
    if raw[0] & 1 or raw == bytes(6):
        raise ValueError('Expected an individual, nonzero MAC address')
    return raw


def mac_text(raw):
    return ':'.join(f'{value:02x}' for value in raw)


def ssid_bytes(ssid):
    raw = ssid.encode('utf-8')
    if not 1 <= len(raw) <= 32:
        raise ValueError('SSID must contain 1..32 UTF-8 bytes')
    return raw


def build_request(kind, ssid, bssid, source=None):
    name, target = ssid_bytes(ssid), mac_bytes(bssid)
    sender = mac_bytes(source) if source is not None else b'\x02' + secrets.token_bytes(5)
    if sender == target:
        raise ValueError('Source must differ from hotspot BSSID')
    if kind == 'auth':
        return struct.pack('<HH', 0x00b0, 0) + target + sender + target + struct.pack('<HHHH', 16, 0, 1, 0)
    if kind == 'probe':
        return (bytes.fromhex('40000000ffffffffffff') + sender + bytes.fromhex('ffffffffffff0000')
                + bytes([0, len(name)]) + name + bytes.fromhex('010882848b960c121824'))
    raise ValueError('Expected auth or probe request')


def elements(data):
    """Extract the baseline view, not a complete management IE representation.

    Unknown/repeatable IDs are traversed but only their first value is exposed.
    Reject ambiguous security/identity inputs for local analysis; this rejection
    alone is not evidence that a receiving STA violated the standard.
    """
    result = {}
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError('Truncated information-element header')
        tag, size = data[offset:offset+2]
        offset += 2
        if offset + size > len(data):
            raise ValueError('Truncated information-element payload')
        if tag in (0, 1, 3, 48, 50, 244) and tag in result:
            raise ValueError(f'Duplicate critical information element {tag}')
        result.setdefault(tag, data[offset:offset+size])
        offset += size
    return result


def rsn_details(raw):
    """Parse RSNE with non-DMG defaults; preserve bytes for exact binding."""
    if raw is None:
        return {'rsn_present': False}
    result = {'rsn_present': True, 'rsn_hex': raw.hex()}
    try:
        if not 2 <= len(raw) <= 255 or struct.unpack_from('<H', raw)[0] != 1:
            raise ValueError('Unsupported or truncated RSN')
        offset, defaults = 2, []
        def take(size):
            nonlocal offset
            if offset + size > len(raw):
                raise ValueError('Truncated RSN field')
            value = raw[offset:offset + size]
            offset += size
            return value
        def optional(name, default, parser):
            if offset == len(raw):
                defaults.append(name)
                return default
            return parser()
        def suites():
            count = int.from_bytes(take(2), 'little')
            if not count:
                raise ValueError('Reserved zero RSN suite count')
            values = take(4 * count)
            return [values[pos:pos + 4].hex() for pos in range(0, len(values), 4)]
        effective = {}
        effective['group_cipher'] = optional('group_cipher', '000fac04', lambda: take(4).hex())
        effective['pairwise_ciphers'] = optional('pairwise_ciphers', ['000fac04'], suites)
        effective['akm_suites'] = optional('akm_suites', ['000fac01'], suites)
        caps = optional('rsn_capabilities', 0, lambda: int.from_bytes(take(2), 'little'))
        if caps & 64 and not caps & 128:
            raise ValueError('MFPR without MFPC')
        count = optional('pmkid_count', 0, lambda: int.from_bytes(take(2), 'little'))
        take(16 * count)
        effective['pmkid_count'] = count
        if offset < len(raw):
            if len(raw) - offset != 4:
                raise ValueError('Invalid group-management cipher or trailing RSN bytes')
            effective['group_management_cipher'] = take(4).hex()
        elif caps & 128:
            effective['group_management_cipher'] = '000fac06'
            defaults.append('group_management_cipher')
        result.update(effective, rsn_defaulted_fields=defaults, rsn_default_context='non_dmg',
                      pmf_capable=bool(caps & 128), pmf_required=bool(caps & 64))
    except (ValueError, struct.error) as exc:
        result['rsn_parse_error'] = str(exc)
    return result


def disconnect_affects_peer(packet, bssid, station):
    """Address scope only; observing a disconnect never proves peer acceptance.

    Include AP broadcasts. Other multicast memberships and protected management
    decryption are outside this legacy observation helper.
    """
    if not packet or packet['subtype'] not in (10, 12) or packet['bssid'] != bssid:
        return False
    source, destination = packet['source'], packet['destination']
    return ((source, destination) in ((bssid, station), (station, bssid)) or
            source == bssid and destination == 'ff:ff:ff:ff:ff:ff')


def management_header(frame):
    """Visible legacy management header only, without authenticating its source.

    Keep the existing no-fragment/no-HT-control profile. Protected payloads
    must not be handed to a plaintext body parser based on this header.
    """
    if len(frame) < 24 or frame[0] & 15 or frame[1] & 0x87 or frame[22] & 15:
        return None
    return {'subtype': frame[0] >> 4, 'destination': mac_text(frame[4:10]),
            'source': mac_text(frame[10:16]), 'bssid': mac_text(frame[16:22]),
            'sequence_control': struct.unpack_from('<H', frame, 22)[0],
            'retry': bool(frame[1] & 8), 'protected_bit': bool(frame[1] & 0x40),
            'source_authenticated': False, 'integrity_valid': None}


def management(frame):
    # No reassembly here: a first fragment is not a complete response.
    if len(frame) < 24 or frame[0] & 15 or frame[1] & 0xc7 or frame[22] & 15:
        return None
    return {'subtype': frame[0] >> 4, 'destination': mac_text(frame[4:10]),
            'source': mac_text(frame[10:16]), 'bssid': mac_text(frame[16:22]),
            'sequence_control': struct.unpack_from('<H', frame, 22)[0],
            'retry': bool(frame[1] & 8), 'body': frame[24:]}


def analyze_capture(path, ssid, bssid=None, request=None, window=4, allow_incomplete=False):
    name = ssid_bytes(ssid)
    target = mac_text(mac_bytes(bssid)) if bssid else None
    if not 0 < window <= 30:
        raise ValueError('Response window must be 0..30 seconds, excluding zero')
    wanted = management(request) if request is not None else None
    if request is not None and (wanted is None or wanted['subtype'] not in (0, 4, 11)):
        raise ValueError('Expected a probe, authentication or association request')
    if wanted:
        mac_bytes(wanted['source'])
        if wanted['subtype'] == 11:
            if len(request) != 30 or wanted['body'] != struct.pack('<HHH', 0, 1, 0):
                raise ValueError('Expected an Open System transaction-1 request without FCS')
            if target and (wanted['destination'] != target or wanted['bssid'] != target):
                raise ValueError('Authentication request target differs from --bssid')
        elif wanted['subtype'] == 0:
            if len(wanted['body']) < 4 or elements(wanted['body'][4:]).get(0) != name:
                raise ValueError('Association request SSID differs from --ssid')
            if target and (wanted['destination'], wanted['bssid']) != (target, target):
                raise ValueError('Association request target differs from --bssid')
        elif elements(wanted['body']).get(0) != name:
            raise ValueError('Probe request SSID differs from --ssid')
    targets, requests, responses, invalid_management = {}, [], [], []
    authentication_observations = []
    capture_quality = {}
    advertised_names = {}
    records = list(captured_records(path, allow_incomplete=allow_incomplete, stats=capture_quality))
    for index, timestamp, frame in records:
        packet = management(frame)
        if packet is None:
            continue
        body, subtype = packet['body'], packet['subtype']
        evidence = {'packet_index': index, 'time': timestamp,
                    'sequence_control': packet['sequence_control'], 'retry': packet['retry']}
        auth = observe_authentication(packet)
        if auth is not None:
            authentication_observations.append({**evidence, **auth})
        if wanted and management_frame_matches(request, frame):
            requests.append({**evidence, 'byte_exact_match': frame == request})
        try:
            ies = elements(body[12:]) if subtype in (5, 8) and len(body) >= 12 else {}
        except ValueError as exc:
            invalid_management.append({**evidence, 'reason': str(exc)})
            continue
        if subtype in (5, 8) and len(body) >= 12:
            if packet['source'] != packet['bssid']:
                invalid_management.append({**evidence, 'reason': 'Advertisement source differs from BSSID'})
                continue
            observed_name = ies.get(0)
            if observed_name is not None and len(observed_name) > 32:
                invalid_management.append({**evidence, 'reason': 'Advertisement SSID exceeds 32 octets'})
                continue
            if observed_name and any(observed_name):
                advertised_names.setdefault(packet['bssid'], set()).add(observed_name.hex())
        if ies.get(0) == name and (target is None or packet['bssid'] == target):
            row = targets.setdefault(packet['bssid'], {'ssid': ssid, 'bssid': packet['bssid'],
                                      'ssid_hex': name.hex(), 'ssid_authentication_confirmed': False,
                                      'beacons': 0, 'probe_responses': 0})
            row['beacons' if subtype == 8 else 'probe_responses'] += 1
            if len(ies.get(3, b'')) == 1:
                row['channel'] = ies[3][0]
            row.update(rsn_details(ies.get(48)))
            row.update(capabilities=struct.unpack_from('<H', body, 10)[0],
                       supported_rates_hex=(ies.get(1, b'') + ies.get(50, b'')).hex())
        if not wanted or target is None or (packet['destination'], packet['source'], packet['bssid']) != (
                wanted['source'], target, target):
            continue
        if subtype in (1, 11) and len(body) >= 6:
            try:
                elements(body[6:])
            except ValueError as exc:
                invalid_management.append({**evidence, 'reason': str(exc)})
                continue
        if wanted['subtype'] == 4 and subtype == 5 and ies.get(0) == name:
            responses.append(evidence)
        if wanted['subtype'] == 11 and subtype == 11 and len(body) >= 6:
            algorithm, transaction, status = struct.unpack_from('<HHH', body)
            if algorithm == 0 and transaction == 2:
                responses.append({**evidence, 'algorithm': algorithm,
                                  'transaction': transaction, 'status_code': status})
        if wanted['subtype'] == 0 and subtype == 1 and len(body) >= 6:
            capabilities, status, aid = struct.unpack_from('<HHH', body)
            responses.append({**evidence, 'status_code': status, 'aid_raw': aid,
                              'aid': aid & 0x3fff, 'capabilities': capabilities,
                              'aid_valid': aid & 0xc000 == 0xc000 and 1 <= aid & 0x3fff <= 2007})
    correlated = []
    for response in responses:
        preceding = [r for r in requests if r['time'] <= response['time'] <= r['time'] + window]
        if preceding:
            # Anchor to first observed request in the window, report retransmissions separately.
            first = preceding[0]
            correlated.append({**response, 'request_packet_index': first['packet_index'],
                               'delay_ms': round((response['time'] - first['time']) * 1000, 3)})
    for address, row in targets.items():
        row['observed_nonhidden_ssids_hex'] = sorted(advertised_names.get(address, set()))
        row['identity_conflict'] = len(row['observed_nonhidden_ssids_hex']) > 1
    return {'target_ssid': ssid, 'target_bssid': target, 'capture_packets': len(records),
            'capture_quality': capture_quality, 'invalid_management': invalid_management,
            'authentication_observations': authentication_observations,
            'targets': list(targets.values()), 'request_observed': bool(requests),
            'request_byte_exact_match': any(r['byte_exact_match'] for r in requests),
            'requests': requests, 'request_retry_frames': sum(r['retry'] for r in requests),
            'response_observed': bool(correlated), 'correlated_responses': correlated,
            'response_retry_frames': sum(r['retry'] for r in correlated),
            'authentication_success_response_observed': bool(wanted and wanted['subtype'] == 11 and
                                                            any(r.get('status_code') == 0 for r in correlated)),
            'association_success_response_observed': bool(wanted and wanted['subtype'] == 0 and
                                                         any(r.get('status_code') == 0 and r.get('aid_valid') for r in correlated)),
            'interpretation': 'Packet indexes refer to the input capture. Capture correlation is observation only. Open System status 0 is not association, password verification or a completed connection.'}
