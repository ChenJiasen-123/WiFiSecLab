"""Bounded WPA2 Open System/association sequence; wire evidence only."""
import struct
from ..network.hotspot import build_request, mac_bytes, mac_text, ssid_bytes


def build_association(ssid, bssid, source, profile, listen_interval=10):
    """Select CCMP/PSK explicitly; do not copy the AP's entire RSN offer.

    This legacy STA profile does not negotiate HT, SAE or PMF-required links.
    """
    name, target, sender = ssid_bytes(ssid), mac_bytes(bssid), mac_bytes(source)
    if profile.get('ssid') != ssid or profile.get('identity_conflict'):
        raise ValueError('Association requires a matching, unambiguous SSID profile')
    if sender == target or profile.get('bssid') != mac_text(target):
        raise ValueError('Association profile/identity mismatch')
    if not 1 <= listen_interval <= 65535:
        raise ValueError('listen_interval must be 1..65535')
    if (profile.get('rsn_parse_error') or profile.get('pmf_required') or
            profile.get('group_cipher') != '000fac04' or
            '000fac04' not in profile.get('pairwise_ciphers', []) or
            '000fac02' not in profile.get('akm_suites', [])):
        raise ValueError('Requires WPA2 PSK/CCMP without required PMF')
    rates = bytes.fromhex(profile.get('supported_rates_hex', ''))
    supported = {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108}
    if not rates or any(rate & 128 and rate & 127 not in supported for rate in rates):
        raise ValueError('Missing rates or unsupported basic rate')
    rates = bytes(dict.fromkeys(rate for rate in rates if rate & 127 in supported))
    if not rates or len(rates) > 12:
        raise ValueError('Invalid rate profile')
    capabilities = profile.get('capabilities', 0)
    if capabilities & 0x11 != 0x11 or capabilities & 2:
        raise ValueError('Expected a privacy-enabled infrastructure AP')
    rsn = bytes.fromhex('0100000fac040100000fac040100000fac020000')
    body = struct.pack('<HH', capabilities & 0x0431, listen_interval)
    body += bytes([0, len(name)]) + name + bytes([1, min(8, len(rates))]) + rates[:8]
    if len(rates) > 8:
        body += bytes([50, len(rates) - 8]) + rates[8:]
    body += bytes([48, len(rsn)]) + rsn
    return struct.pack('<HH', 0, 0) + target + sender + target + struct.pack('<H', 32) + body


def stage_outcome(report, kind):
    """Never choose a success from contradictory response statuses."""
    if not report.get('request_observed'):
        return 'unknown_request_not_observed'
    responses = report.get('correlated_responses', [])
    statuses = {row['status_code'] for row in responses}
    if not statuses:
        return 'unknown_no_response'
    if len(statuses) != 1:
        return 'ambiguous_conflicting_responses'
    if statuses != {0}:
        return 'rejected'
    if kind == 'association' and not all(row.get('aid_valid') for row in responses):
        return 'unexpected_invalid_aid'
    return 'success_response_observed'


def run_sequence(ssid, bssid, source, profile, exchange):
    """exchange(kind, request) returns an independently correlated capture report.

    Exactly one application submission per step; driver retries remain separate.
    A new source address does not prove the AP was reset.
    """
    association = build_association(ssid, bssid, source, profile)  # validate before sending
    steps = []
    for kind, frame in [('authentication', build_request('auth', ssid, bssid, source)),
                        ('association', association)]:
        report = exchange(kind, frame)
        outcome = stage_outcome(report, kind)
        steps.append({'kind': kind, 'request_hex': frame.hex(), 'outcome': outcome, 'evidence': report})
        if outcome != 'success_response_observed':
            break
    return {'source': source, 'bssid': bssid, 'steps': steps,
            'association_response_confirmed': len(steps) == 2 and steps[-1]['outcome'] == 'success_response_observed',
            'ap_reset_confirmed': False, 'key_installation_confirmed': False,
            'data_authorization_confirmed': False,
            'interpretation': 'Responses describe advertised behavior; no internal AP state or completed WPA2 handshake is proven.'}
