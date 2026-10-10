"""Capture-backed admission to an initial legacy WPA2 handshake session."""
import hashlib
import math
import struct
from ..network.hotspot import management, elements, disconnect_affects_peer
from ..network.physical import management_frame_matches
from .wpa2_session import HandshakeSession


def association_evidence(association, records, *, now, window=2):
    """records: ordered (monotonic_time, validated_raw_80211_bytes) pairs.

    Evidence is local capture correlation, not AP identity authentication.
    Caller must validate radiotap/FCS/truncation and keep a single clock domain.
    """
    request = management(association)
    if request is None or request['subtype'] != 0 or request['destination'] != request['bssid']:
        raise ValueError('Initial association request required')
    if (type(now) not in (int, float) or not math.isfinite(now) or now < 0 or
            type(window) not in (int, float) or not math.isfinite(window) or not 0 < window <= 10):
        raise ValueError('Invalid association evidence time window')
    ap, sta = request['bssid'], request['source']
    if ap == sta:
        raise ValueError('Distinct AP and station required')
    requests, responses, reasons = [], [], []
    previous = None
    for index, (timestamp, frame) in enumerate(records):
        if index >= 4096:
            raise ValueError('Association evidence record budget exceeded')
        if (type(timestamp) not in (int, float) or not math.isfinite(timestamp) or
                timestamp < 0 or timestamp > now or previous is not None and timestamp < previous or
                not isinstance(frame, bytes)):
            raise ValueError('Ordered finite capture times and raw bytes required')
        previous = timestamp
        if timestamp < now - window:
            continue
        packet = management(frame)
        if packet is None:
            continue
        if management_frame_matches(association, frame):
            requests.append({'record_index': index, 'time': timestamp})
            continue
        same_peer = (packet['bssid'] == ap and
                     {packet['source'], packet['destination']} == {ap, sta})
        if not requests:
            continue
        if disconnect_affects_peer(packet, ap, sta):
            reasons.append('management_boundary_after_request')
            continue
        if not same_peer:
            continue
        if packet['subtype'] in (0, 2, 10, 11, 12):
            reasons.append('management_boundary_after_request')
            continue
        if packet['subtype'] != 1 or (packet['source'], packet['destination']) != (ap, sta):
            continue
        body = packet['body']
        if len(body) < 6:
            reasons.append('truncated_association_response')
            continue
        caps, status, aid = struct.unpack_from('<HHH', body)
        try:
            ies = elements(body[6:])
        except ValueError:
            reasons.append('malformed_response_elements')
            continue
        row = {'record_index': index, 'time': timestamp, 'status_code': status,
               'aid_raw': aid, 'aid': aid & 0x3fff,
               'frame_sha256': hashlib.sha256(frame).hexdigest()}
        responses.append(row)
        if status != 0:
            reasons.append('nonzero_status_outside_initial_success_profile')
        elif aid & 0xc000 != 0xc000 or not 1 <= aid & 0x3fff <= 2007:
            reasons.append('invalid_legacy_aid')
        if status == 0 and (not 1 <= len(ies.get(1, b'')) <= 8 or caps & 3 != 1):
            reasons.append('unsupported_or_missing_infrastructure_rate_profile')
    if not requests:
        reasons.append('no_recent_request_observed')
    if not responses:
        reasons.append('no_correlated_response_observed')
    if len({(row['status_code'], row['aid_raw']) for row in responses}) > 1:
        reasons.append('conflicting_responses')
    return {'eligible': not reasons, 'reasons': sorted(set(reasons)), 'bssid': ap, 'station': sta,
            'request_sha256': hashlib.sha256(association).hexdigest(),
            'requests': requests, 'responses': responses, 'evaluated_at': now, 'window': window,
            'ap_internal_association_confirmed': False, 'ap_identity_authenticated': False}


def admitted_session(association, advertisement, pmk, records, *, now, window=2, **options):
    """Construct a session only after an unambiguous captured success response."""
    evidence = association_evidence(association, records, now=now, window=window)
    if not evidence['eligible']:
        raise ValueError('Association evidence does not permit a new handshake session')
    session = HandshakeSession(association, advertisement, pmk, started_at=now, **options)
    session.admission_evidence = evidence
    return session
