"""Common authentication observations for AP state tests, not acceptance events."""
import struct


def observe_authentication(packet):
    """Accept a decoded, unfragmented management packet with FCS removed.

    Algorithm-specific payload is preserved without pretending to validate SAE,
    FT or FILS cryptography. Identity correlation belongs to the scenario layer.
    """
    if packet is None or packet.get('subtype') != 11:
        return None
    result = {key: packet[key] for key in
              ('source', 'destination', 'bssid', 'sequence_control', 'retry')}
    result.update(ap_internal_acceptance_confirmed=False,
                  peer_completion_confirmed=False, fcs_validation_confirmed=False)
    body = packet['body']
    if len(body) < 6:
        result['parse_error'] = 'Truncated authentication fixed fields'
        result['body_hex'] = body.hex()
        return result
    algorithm, transaction, status = struct.unpack_from('<HHH', body)
    result.update(algorithm=algorithm, transaction=transaction,
                  status_code=status, payload_hex=body[6:].hex(),
                  payload_validation='not_performed')
    return result
