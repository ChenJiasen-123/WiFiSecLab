"""Redacted parsing of unwrapped M3 Key Data for a baseline CCMP profile."""
from ..network.hotspot import rsn_details


def parse_m3_key_data(data):
    """Never return GTK bytes or arbitrary unknown element payloads.

    Two RSNEs can be valid in IEEE 802.11, but their override semantics and
    RSNXE/other ciphers are outside this profile. Unknown elements are ignored.
    """
    if not isinstance(data, bytes) or len(data) < 16 or len(data) % 8:
        raise ValueError('Invalid unwrapped AES Key Data length')
    offset, padding, unknown = 0, 0, 0
    rsnes, gtk, rsnxe = [], None, False
    rsnxe_capabilities = None
    while offset < len(data):
        tail = data[offset:]
        if tail[0] == 221 and not any(tail[1:]):
            padding = len(tail)
            break
        if len(tail) >= 2 and tail[:2] == b'\xdd\x00':
            raise ValueError('Nonzero bytes after Key Data padding marker')
        if len(tail) < 2 or tail[1] + 2 > len(tail):
            raise ValueError('Truncated Key Data element')
        tag, length = tail[:2]
        value = tail[2:2 + length]
        offset += 2 + length
        if tag == 48:
            details = rsn_details(value)
            if details.get('rsn_parse_error'):
                raise ValueError('Malformed M3 RSNE')
            rsnes.append(value)
        elif tag == 244:
            if rsnxe:
                raise ValueError('Duplicate M3 RSNXE')
            if not 1 <= len(value) <= 16 or (value[0] & 15) + 1 != len(value):
                raise ValueError('Invalid RSNXE capabilities field length')
            rsnxe = True
            rsnxe_capabilities = {
                'field_length': len(value),
                'spp_amsdu_capable_advertised': bool(int.from_bytes(value, 'little') & (1 << 14)),
                'negotiation_confirmed': False,
            }
        elif tag == 221 and value[:4] == bytes.fromhex('000fac01'):
            if gtk is not None or len(value) < 6:
                raise ValueError('Duplicate or truncated GTK KDE')
            # Figure 12-38 in 802.11-2024 marks bit 2 reserved.
            # It must not be reported as GTK transmit authorization.
            gtk = {'key_id': value[4] & 3,
                   'reserved_bit_2_set': bool(value[4] & 4),
                   'reserved_zero': not (value[4] & 0xfc or value[5]),
                   'layout_revision': 'IEEE 802.11-2024 Figure 12-38',
                   'key_length': len(value) - 6}
        else:
            unknown += 1
    if not 1 <= len(rsnes) <= 2:
        raise ValueError('M3 requires one or two RSNEs')
    group_ccmp = rsn_details(rsnes[0]).get('group_cipher') == '000fac04'
    if group_ccmp and (gtk is None or gtk['key_length'] != 16):
        raise ValueError('CCMP M3 requires a 16-byte GTK')
    return {'rsne_hex': [r.hex() for r in rsnes], 'rsnxe_present': rsnxe,
            'rsnxe_capabilities': rsnxe_capabilities,
            'gtk': gtk, 'padding_length': padding, 'unknown_elements_ignored': unknown,
            'baseline_profile_supported': len(rsnes) == 1 and not rsnxe and group_ccmp}
