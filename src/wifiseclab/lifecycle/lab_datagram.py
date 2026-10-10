"""Normal lab datagram construction; no socket or radio operations."""
import struct
from ..network.ccmp import baseline_data_aad
from wifiseclab.lifecycle.udp_evidence import checksum


def lab_request(token, source_port=51000):
    if not isinstance(token, bytes) or len(token) != 16:
        raise ValueError('Expected 128-bit lab challenge')
    if type(source_port) is not int or not 1 <= source_port <= 65535:
        raise ValueError('Invalid UDP source port')
    payload = b'WiFiSecLab-request:' + token
    source, destination = bytes([192,0,2,2]), bytes([192,0,2,1])
    length = 8 + len(payload)
    udp = bytearray(struct.pack('!HHHH',source_port,49321,length,0) + payload)
    pseudo = source + destination + bytes([0,17]) + length.to_bytes(2,'big')
    udp[6:8] = (checksum(pseudo + udp) or 65535).to_bytes(2,'big')
    ip = bytearray(struct.pack('!BBHHHBBH',69,0,20+length,0,16384,64,17,0) + source + destination)
    ip[10:12] = checksum(ip).to_bytes(2,'big')
    return bytes.fromhex('aaaa030000000800') + bytes(ip) + bytes(udp)


class LabCcmpUplink:
    """One fresh lab TK context, monotonically allocating PN before encryption.

    Caller must create exactly one allocator for a fresh TK; never recreate it
    for the same key. No retries or caller-selected PN are exposed.
    """
    def __init__(self, tk, ap, station):
        if not isinstance(tk,bytes) or len(tk)!=16:
            raise ValueError('Expected CCMP-128 TK')
        if (not isinstance(ap,bytes) or not isinstance(station,bytes)
                or len(ap)!=6 or len(station)!=6 or ap==station or ap[0]&1 or station[0]&1):
            raise ValueError('Distinct unicast MAC identities required')
        self._tk,self.ap,self.station=tk,ap,station
        self._next_pn=1
        self._next_sequence=0  # Separate modulo-4096 MAC sequence space.

    def build_request(self, token):
        plaintext=lab_request(token)
        if self._next_pn >= 1<<48:
            raise ValueError('PN exhausted; new TK required')
        pn=self._next_pn;self._next_pn+=1
        sequence=self._next_sequence
        self._next_sequence=(sequence+1)%4096
        header=bytes.fromhex('08410000')+self.ap+self.station+self.ap+(sequence<<4).to_bytes(2,'little')
        aad=baseline_data_aad(header)
        pn_le=pn.to_bytes(6,'little')
        ccmp=pn_le[:2]+bytes([0,32])+pn_le[2:]
        nonce=bytes(1)+self.station+pn.to_bytes(6,'big')
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
        return header+ccmp+AESCCM(self._tk,tag_length=8).encrypt(nonce,plaintext,aad)
