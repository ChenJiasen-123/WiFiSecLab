"""MME decoding and offline BIP-CMAC checks; no receiver-state inference."""


def decode_mme(element, *, cipher=None):
    """Decode one exact MME IE, including ID/length and excluding FCS.

    The cipher must come from independent negotiated context. A 16-octet MIC
    alone cannot distinguish CMAC-256 from either GMAC cipher.
    """
    if not isinstance(element, (bytes, bytearray)) or len(element) not in (18, 26):
        raise ValueError('Expected an exact MME of 18 or 26 octets')
    if element[0] != 76 or element[1] != len(element) - 2:
        raise ValueError('MME identity or length mismatch')
    key_id = int.from_bytes(element[2:4], 'little')
    if key_id not in (4, 5, 6, 7):
        raise ValueError('Reserved MME Key ID or reserved Key ID bits')
    mic_length = len(element) - 10
    lengths = {'BIP-CMAC-128': 8, 'BIP-CMAC-256': 16,
               'BIP-GMAC-128': 16, 'BIP-GMAC-256': 16}
    if cipher is not None:
        if cipher not in lengths or lengths[cipher] != mic_length:
            raise ValueError('Unsupported cipher or MME MIC length mismatch')
    return {'key_id': key_id, 'key_type': 'IGTK' if key_id in (4, 5) else 'BIGTK',
            'ipn_or_bipn': int.from_bytes(element[4:10], 'little'),
            'mic_length': mic_length, 'cipher_context': cipher,
            'integrity_valid': None, 'replay_validation': 'unknown',
            'receiver_acceptance_confirmed': False}


def verify_group_disconnect(frame, key, *, cipher, transmitter, key_id,
                            replay_floor=None):
    """Check a legacy group deauth/disassoc with a supplied integrity key.

    Input excludes radiotap and FCS. Caller binds key/cipher/transmitter/Key ID
    to independent evidence. This function neither sends frames nor updates
    any replay ledger; a provided floor is not a proven receiver configuration.
    """
    import hmac
    from ..network.hotspot import management_header, mac_bytes

    sizes = {'BIP-CMAC-128': (16, 8), 'BIP-CMAC-256': (32, 16)}
    if cipher not in sizes:
        raise ValueError('Only BIP-CMAC-128/256 are supported by this verifier')
    key_length, mic_length = sizes[cipher]
    if not isinstance(key, bytes) or len(key) != key_length:
        raise ValueError('Integrity key length differs from the supplied cipher')
    if not isinstance(frame, bytes) or len(frame) != 24 + 2 + 10 + mic_length:
        raise ValueError('Expected exact group disconnect with final MME, without FCS')
    if type(key_id) is not int or key_id not in (4, 5):
        raise ValueError('An explicit IGTK Key ID of 4 or 5 is required')
    if replay_floor is not None and (type(replay_floor) is not int or
                                    not 0 <= replay_floor < 1 << 48):
        raise ValueError('Replay floor must be a 48-bit unsigned integer')
    header = management_header(frame)
    if (header is None or header['subtype'] not in (10, 12) or not frame[4] & 1
            or frame[10:16] != mac_bytes(transmitter)):
        raise ValueError('Frame does not match the supplied group management context')
    summary = decode_mme(frame[26:], cipher=cipher)
    if summary['key_id'] != key_id:
        raise ValueError('MME Key ID differs from the supplied IGTK context')
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms

    # Standard 12.5.3.3: mask Retry/PwrMgt/MoreData, retain other FC bits.
    aad = bytes((frame[0], frame[1] & ~0x38)) + frame[4:22]
    body = frame[24:-mic_length] + bytes(mic_length)
    cmac = CMAC(algorithms.AES(key))
    cmac.update(aad + body)
    valid = hmac.compare_digest(cmac.finalize()[:mic_length], frame[-mic_length:])
    fresh = None if replay_floor is None else summary['ipn_or_bipn'] > replay_floor
    summary.update(integrity_valid=valid, source_authenticated=False,
                   integrity_scope='supplied_group_key_context',
                   replay_validation='unknown' if fresh is None else
                   ('above_supplied_floor' if fresh else 'not_above_supplied_floor'),
                   next_floor_candidate=summary['ipn_or_bipn'] if valid and fresh is True else None,
                   receiver_configuration_confirmed=False)
    return summary
