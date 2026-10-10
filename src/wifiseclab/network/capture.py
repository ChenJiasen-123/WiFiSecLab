"""Normalize capture metadata before interpreting protocol evidence.

Radiotap flags are authoritative about FCS presence; never guess from length.
Only the initial namespace's TSFT and Flags fields are decoded here.
"""
import struct
import zlib


def decode_radiotap(packet, stats=None):
    def count(name):
        if stats is not None:
            stats[name] = stats.get(name, 0) + 1
    if len(packet) < 8 or packet[0] != 0:
        raise ValueError('Invalid or unsupported radiotap header')
    length = struct.unpack_from('<H', packet, 2)[0]
    if not 8 <= length <= len(packet):
        raise ValueError('Invalid radiotap length')
    first = word = struct.unpack_from('<I', packet, 4)[0]
    cursor = 8
    while word & 0x80000000:
        if cursor + 4 > length:
            raise ValueError('Truncated radiotap presence bitmap')
        word = struct.unpack_from('<I', packet, cursor)[0]
        cursor += 4
    if first & 1:
        cursor = (cursor + 7) & ~7
        cursor += 8
    if cursor > length or (first & 2 and cursor >= length):
        raise ValueError('Truncated radiotap TSFT/Flags')
    flags = packet[cursor] if first & 2 else 0
    frame = packet[length:]
    if flags & 0x40:
        count('driver_bad_fcs')
        return None
    # Padded non-management layouts need a full MAC-header parser before CRC.
    if flags & 0x20 and (len(frame) < 2 or frame[0] & 0x0c or frame[1] & 0x80):
        count('unsupported_padded_layout')
        return None
    if flags & 0x10:
        if len(frame) < 4:
            raise ValueError('FCS flag without four FCS octets')
        body, received = frame[:-4], struct.unpack_from('<I', frame, len(frame) - 4)[0]
        if zlib.crc32(body) & 0xffffffff != received:
            count('software_bad_fcs')
            return None
        count('fcs_verified')
        frame = body
    else:
        count('fcs_not_available')
    count('accepted_frames')
    return frame
