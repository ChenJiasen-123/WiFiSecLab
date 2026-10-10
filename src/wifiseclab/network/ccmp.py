"""Offline CCMP-128 integrity verification for baseline unicast PV0 data.

No receiver replay decision, transmission, key installation or AP acceptance.
"""
from ..protocol.wpa2 import derive_kck
import hmac


def derive_tk(pmk, ap, station, anonce, snonce):
    derive_kck(pmk, ap, station, anonce, snonce)
    context = min(ap, station) + max(ap, station) + min(anonce, snonce) + max(anonce, snonce)
    prefix = b'Pairwise key expansion\x00' + context
    return b''.join(hmac.new(pmk, prefix + bytes([i]), 'sha1').digest()
                    for i in range(3))[32:48]



def baseline_data_aad(header):
    """IEEE 802.11-2024 12.5.2.3.3: canonical AAD for this data profile.

    Exact MAC header only; three addresses, PV0, no fragments/HTC/A-MSDU.
    Negotiation and peer binding remain the caller's responsibility.
    """
    if not isinstance(header, bytes) or len(header) not in (24, 26):
        raise ValueError('Expected an exact baseline MAC header')
    subtype = header[0] >> 4
    qos = subtype == 8
    if (header[0] & 15 != 8 or subtype not in (0, 8) or
            len(header) != (26 if qos else 24) or
            header[1] & 3 not in (1, 2) or not header[1] & 64 or
            header[1] & 132 or header[22] & 15 or
            qos and header[24] & 128):
        raise ValueError('Unsupported MAC context for baseline AAD')
    aad = bytes([header[0] & 143, header[1] & 199]) + header[4:22] + bytes(2)
    return aad + bytes([header[24] & 15, 0]) if qos else aad


def decrypt_unicast(frame, tk, ap, station):
    """Return verified plaintext bytes; caller must not log arbitrary plaintext.

    Raw 802.11 frame excludes radiotap/FCS. Reject unsupported formats rather
    than guessing AAD, negotiation, GTK or replay-counter context.
    """
    if not isinstance(tk, bytes) or len(tk) != 16:
        raise ValueError('Expected CCMP-128 temporal key')
    if not isinstance(frame, bytes) or len(frame) < 40:
        raise ValueError('Truncated CCMP frame')
    if len(ap) != 6 or len(station) != 6 or ap == station:
        raise ValueError('Distinct AP/STA MAC bytes required')
    subtype = frame[0] >> 4
    if frame[0] & 15 != 8 or subtype not in (0, 8):
        raise ValueError('Unsupported protocol/type/subtype')
    ds = frame[1] & 3
    if ds not in (1, 2) or not frame[1] & 64 or frame[1] & 132 or frame[22] & 15:
        raise ValueError('Requires protected unfragmented three-address data without HTC')
    receiver, transmitter = frame[4:10], frame[10:16]
    if receiver[0] & 1 or transmitter[0] & 1:
        raise ValueError('Requires individually addressed traffic')
    if (ds == 1 and (receiver, transmitter) != (ap, station)
            or ds == 2 and (receiver, transmitter) != (station, ap)):
        raise ValueError('Frame does not belong to configured AP/STA pair')
    qos = subtype == 8
    offset = 26 if qos else 24
    if len(frame) < offset + 16:
        raise ValueError('Truncated CCMP payload')
    if qos and frame[24] & 128:
        raise ValueError('A-MSDU is outside the non-aggregated CCMP profile')
    priority = frame[24] & 15 if qos else 0
    aad = baseline_data_aad(frame[:offset])
    header = frame[offset:offset + 8]
    if header[2] != 0 or header[3] != 32:
        raise ValueError('Requires baseline pairwise Key ID zero and ExtIV only')
    pn_le = header[:2] + header[4:8]
    if pn_le == bytes(6):
        raise ValueError('PN zero is outside the selected profile')
    nonce = bytes([priority]) + transmitter + pn_le[::-1]
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from cryptography.exceptions import InvalidTag
    try:
        plaintext = AESCCM(tk, tag_length=8).decrypt(nonce, frame[offset + 8:], aad)
    except InvalidTag as exc:
        raise ValueError('CCMP integrity verification failed') from exc
    return {'plaintext': plaintext, 'pn': int.from_bytes(pn_le, 'little'),
            'priority': priority, 'direction': 'uplink' if ds == 1 else 'downlink',
            'mic_valid': True, 'receiver_acceptance_confirmed': False,
            # MIC success authenticates canonical AAD, not the whole MAC header.
            'integrity_scope': {
                'profile': 'CCMP-128/PV0/three-address/unicast/non-aggregated',
                'aad_length': len(aad),
                'authenticated_address_fields': ['A1', 'A2', 'A3'],
                'authenticated_sequence_fields': ['fragment_number'],
                'masked_or_excluded_fields': [
                    'duration_id', 'retry', 'power_management', 'more_data',
                    'sequence_number', 'data_subtype_bits_4_6',
                ] + (['qos_bits_except_tid', 'htc_presence'] if qos else []),
                'payload_interpretation': 'single_msdu_only',
                'replay_checked': False,
            }}
