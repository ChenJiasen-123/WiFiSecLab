"""Known-key WPA2/CCMP packet construction for offline laboratory use."""
import hashlib
import hmac
import secrets
import struct
from ..network.hotspot import mac_bytes, elements, management, rsn_details


def derive_kck(pmk, ap, station, anonce, snonce):
    if not isinstance(pmk, bytes) or len(pmk) != 32:
        raise ValueError('A single known 32-byte PMK is required')
    if (any(not isinstance(peer, bytes) or len(peer) != 6 or
                peer == bytes(6) or peer[0] & 1 for peer in (ap, station))
            or ap == station):
        raise ValueError('Distinct individual nonzero six-byte AP/STA identities required')
    if any(not isinstance(n, bytes) or len(n) != 32 or n == bytes(32) for n in (anonce, snonce)):
        raise ValueError('Nonzero 32-byte ANonce and SNonce required')
    context = min(ap, station) + max(ap, station) + min(anonce, snonce) + max(anonce, snonce)
    return hmac.new(pmk, b'Pairwise key expansion\x00' + context + b'\x00', 'sha1').digest()[:16]


def key_mic(raw, kck):
    """MIC for the selected PSK/CCMP baseline, on one exact EAPOL PDU.

    Descriptor version is a consistency check, not AKM negotiation evidence.
    The caller must supply the negotiated profile and strip outer MSDU tails.
    """
    if (not isinstance(raw, (bytes, bytearray)) or len(raw) < 99 or
            not isinstance(kck, bytes) or len(kck) != 16):
        raise ValueError('Expected baseline EAPOL bytes and a 16-byte KCK')
    if (raw[0] not in (1, 2, 3) or raw[1] != 3 or raw[4] != 2 or
            (int.from_bytes(raw[5:7], 'big') & 7) != 2):
        raise ValueError('Unsupported EAPOL-Key layout for the selected PSK/CCMP profile')
    if (int.from_bytes(raw[2:4], 'big') != len(raw) - 4 or
            int.from_bytes(raw[97:99], 'big') != len(raw) - 99):
        raise ValueError('MIC input must be one exact length-consistent EAPOL-Key PDU')
    unsigned = raw[:81] + bytes(16) + raw[97:]
    return hmac.new(kck, unsigned, 'sha1').digest()[:16]


def derive_kek(pmk, ap, station, anonce, snonce):
    """The next 16 PTK bytes; SHA1 PRF blocks are 20 bytes, not 16."""
    derive_kck(pmk, ap, station, anonce, snonce)  # shared input validation
    context = min(ap, station) + max(ap, station) + min(anonce, snonce) + max(anonce, snonce)
    prefix = b'Pairwise key expansion\x00' + context
    material = b''.join(hmac.new(pmk, prefix + bytes([i]), 'sha1').digest() for i in range(2))
    return material[16:32]


def unwrap_key_data(wrapped, kek):
    """RFC3394 integrity-checked unwrap. Caller must verify EAPOL MIC first.

    Returns sensitive plaintext to the caller; never include it in reports.
    IEEE 802.11 padding/IE interpretation is a separate operation.
    """
    if not isinstance(kek, bytes) or len(kek) != 16:
        raise ValueError('Expected 16-byte KEK for this profile')
    if not isinstance(wrapped, bytes) or len(wrapped) < 24 or len(wrapped) % 8:
        raise ValueError('Invalid RFC3394 wrapped data length')
    try:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
    except ImportError as exc:
        raise ValueError('Install wifiseclab[crypto] to unwrap key data') from exc
    try:
        return aes_key_unwrap(kek, wrapped)
    except InvalidUnwrap as exc:
        raise ValueError('AES key data integrity check failed') from exc


def build_m2(m1, association, pmk, snonce=None, sequence=0, eapol_version=2):
    """Construct one response bound to an observed M1 and selected association RSNE.

    No transmission or AP-acceptance inference. SAE/FT/PMF/OCI are unsupported.
    """
    from wifiseclab.protocol.eapol import decode_key
    if not isinstance(pmk, bytes) or len(pmk) != 32:
        raise ValueError('A single known 32-byte PMK is required')
    assoc = management(association)
    if assoc is None or assoc['subtype'] != 0 or len(assoc['body']) < 4:
        raise ValueError('Expected an unfragmented association request without FCS')
    ap, sta = mac_bytes(assoc['bssid']), mac_bytes(assoc['source'])
    if assoc['destination'] != assoc['bssid'] or ap == sta:
        raise ValueError('Association addresses do not identify this AP/STA pair')
    ies = elements(assoc['body'][4:])
    if not 1 <= len(ies.get(0, b'')) <= 32 or 48 not in ies or 244 in ies:
        raise ValueError('Expected SSID/RSNE without RSNXE')
    rsn = ies[48]
    details = rsn_details(rsn)
    if (details.get('rsn_parse_error') or details.get('group_cipher') != '000fac04' or
        details.get('pairwise_ciphers') != ['000fac04'] or details.get('akm_suites') != ['000fac02'] or
        details.get('pmf_capable') or details.get('pmf_required') or details.get('pmkid_count', 0)):
        raise ValueError('Requires a single selected WPA2 PSK/CCMP suite without PMF/PMKID')
    # This profile intentionally omits OCI, Extended Key ID and other extensions.
    if len(rsn) != 20 or rsn[-2:] != bytes(2):
        raise ValueError('Requires baseline RSN capabilities without extensions')
    key = decode_key(m1, assoc['bssid'], assoc['source'])
    if key is None or key['message'] != 1 or key['issues'] or key['key_length'] != 16:
        raise ValueError('Expected a valid-profile M1 for the association identities')
    raw = key['_eapol']
    if any(raw[49:99-2]):  # IV, RSC, reserved Key ID and absent-MIC storage must be zero.
        raise ValueError('M1 reserved/IV/RSC/MIC fields are not zero')
    if key['key_data_length']:
        data = elements(raw[99:])
        expected = bytes.fromhex('000fac04') + hmac.new(pmk, b'PMK Name' + ap + sta, 'sha1').digest()[:16]
        if data != {221: expected} or len(raw[99:]) != 22:
            raise ValueError('M1 PMKID does not match the configured PMK/profile')
    if type(sequence) is not int or not 0 <= sequence <= 4095 or eapol_version not in (1, 2, 3):
        raise ValueError('Invalid sequence or EAPOL version')
    snonce = secrets.token_bytes(32) if snonce is None else snonce
    kck = derive_kck(pmk, ap, sta, bytes.fromhex(key['nonce_hex']), snonce)
    data = bytes([48, len(rsn)]) + rsn
    body = bytearray(95)
    body[0] = 2
    struct.pack_into('!H', body, 1, 0x010a)
    body[5:13] = key['replay_counter'].to_bytes(8, 'big')
    body[13:45] = snonce
    struct.pack_into('!H', body, 93, len(data))
    reply = bytearray(struct.pack('!BBH', eapol_version, 3, len(body) + len(data)) + body + data)
    reply[81:97] = key_mic(reply, kck)
    header = struct.pack('<HH', 0x0108, 0) + ap + sta + ap + struct.pack('<H', sequence << 4)
    return header + bytes.fromhex('aaaa03000000888e') + reply


def build_m4(m1, m2, m3, association, advertisement, pmk, sequence=0, eapol_version=2):
    """Offline initial-handshake response for one validated, single-flight branch.

    Inputs alone do not establish reception order, freshness or AP acceptance.
    The caller must maintain the session/replay history before any live use.
    No key installation, transmission or data-port authorization is performed.
    """
    from wifiseclab.protocol.eapol import decode_key
    from wifiseclab.protocol.keydata import parse_m3_key_data
    assoc = management(association)
    if assoc is None:
        raise ValueError('Missing association context')
    bssid, station = assoc['bssid'], assoc['source']
    second = decode_key(m2, bssid, station)
    if second is None or second['message'] != 2 or second['issues']:
        raise ValueError('Expected M2 from the selected station')
    snonce = bytes.fromhex(second['nonce_hex'])
    expected = build_m2(m1, association, pmk, snonce, eapol_version=second['_eapol'][0])
    if not hmac.compare_digest(expected[32:], second['_eapol']):
        raise ValueError('M2 differs from the selected M1/association/PMK context')
    first, third = decode_key(m1, bssid, station), decode_key(m3, bssid, station)
    if (third is None or third['message'] != 3 or third['issues'] or
            third['nonce_hex'] != first['nonce_hex'] or
            third['replay_counter'] <= first['replay_counter']):
        raise ValueError('M3 flags, fields, nonce or replay counter do not match')
    ap, sta = mac_bytes(bssid), mac_bytes(station)
    anonce = bytes.fromhex(first['nonce_hex'])
    kck = derive_kck(pmk, ap, sta, anonce, snonce)
    raw = third['_eapol']
    if not hmac.compare_digest(raw[81:97], key_mic(raw, kck)):
        raise ValueError('M3 MIC validation failed')
    summary = parse_m3_key_data(unwrap_key_data(raw[99:], derive_kek(pmk, ap, sta, anonce, snonce)))
    # Conservative construction profile, not an AP conformance verdict.
    if not summary['baseline_profile_supported'] or not summary['gtk']['reserved_zero']:
        raise ValueError('M3 requires unsupported Key Data semantics')
    advertised = management(advertisement)
    if (advertised is None or advertised['subtype'] not in (5, 8) or len(advertised['body']) < 12 or
            advertised['source'] != bssid or advertised['bssid'] != bssid or
            advertised['destination'] != ('ff:ff:ff:ff:ff:ff' if advertised['subtype'] == 8 else station)):
        raise ValueError('Expected a matching AP Beacon or directed Probe Response')
    offer = elements(advertised['body'][12:])
    selected = elements(assoc['body'][4:])
    if offer.get(0) != selected[0] or 244 in offer or 48 not in offer:
        raise ValueError('Advertisement SSID/RSNE context differs or is unsupported')
    capabilities = rsn_details(offer[48])
    if (capabilities.get('rsn_parse_error') or capabilities.get('pmf_required') or
            '000fac02' not in capabilities.get('akm_suites', []) or
            '000fac04' not in capabilities.get('pairwise_ciphers', []) or
            capabilities.get('group_cipher') != '000fac04' or
            offer[48].hex() != summary['rsne_hex'][0]):
        raise ValueError('M3 RSNE differs from the compatible AP advertisement')
    if type(sequence) is not int or not 0 <= sequence <= 4095 or eapol_version not in (1, 2, 3):
        raise ValueError('Invalid sequence or EAPOL version')
    body = bytearray(95)
    body[0] = 2
    struct.pack_into('!H', body, 1, 0x030a)
    body[5:13] = third['replay_counter'].to_bytes(8, 'big')
    reply = bytearray(struct.pack('!BBH', eapol_version, 3, 95) + body)
    reply[81:97] = key_mic(reply, kck)
    header = struct.pack('<HH', 0x0108, 0) + ap + sta + ap + struct.pack('<H', sequence << 4)
    return header + bytes.fromhex('aaaa03000000888e') + reply
