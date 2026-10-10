"""Strict baseline IPv4/UDP parsing of integrity-verified LLC payloads."""
import ipaddress


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def parse_udp(plaintext):
    if not isinstance(plaintext, bytes) or plaintext[:8] != bytes.fromhex('aaaa030000000800'):
        raise ValueError('Requires IPv4 LLC/SNAP')
    ip = plaintext[8:]
    if len(ip) < 28 or ip[0] != 69:
        raise ValueError('Requires complete IPv4 without options')
    if int.from_bytes(ip[2:4], 'big') != len(ip):
        raise ValueError('IPv4 length mismatch')
    if int.from_bytes(ip[6:8], 'big') & 49151:
        raise ValueError('IPv4 fragments/reserved flag unsupported')
    if ip[9] != 17 or checksum(ip[:20]):
        raise ValueError('Not UDP or bad IPv4 checksum')
    udp = ip[20:]
    if int.from_bytes(udp[4:6], 'big') != len(udp):
        raise ValueError('UDP length mismatch or unsupported trailing options')
    sport, dport = int.from_bytes(udp[:2], 'big'), int.from_bytes(udp[2:4], 'big')
    if not sport or not dport:
        raise ValueError('Zero ports outside selected lab profile')
    checked = udp[6:8] != bytes(2)
    pseudo = ip[12:20] + bytes([0, 17]) + len(udp).to_bytes(2, 'big')
    if checked and checksum(pseudo + udp):
        raise ValueError('UDP checksum mismatch')
    return {'source': [str(ipaddress.IPv4Address(ip[12:16])), sport],
            'destination': [str(ipaddress.IPv4Address(ip[16:20])), dport],
            'payload': udp[8:], 'udp_checksum_verified': checked}
