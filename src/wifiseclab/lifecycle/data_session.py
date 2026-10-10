"""One bounded normal UDP challenge on an established baseline PSK/CCMP context.

Caller establishes fresh TK and owns transport. This object never transmits.
Observed boundaries close local context; they do not prove AP acceptance.
"""
import math
from ..network.hotspot import mac_bytes, mac_text, management, disconnect_affects_peer
from ..network.ccmp import decrypt_unicast
from wifiseclab.lifecycle.lab_datagram import LabCcmpUplink
from wifiseclab.lifecycle.udp_evidence import parse_udp


class DataSession:
    def __init__(self, tk, ap, station, token, *, started_at, timeout=2):
        if (type(started_at) not in (int,float) or not math.isfinite(started_at) or started_at<0
                or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=5
                or not isinstance(token,bytes) or len(token)!=16):
            raise ValueError('Invalid bounded data-session context')
        self.sender=LabCcmpUplink(tk,ap,station)
        self.tk,self.ap,self.station,self.token=tk,ap,station,token
        self.deadline,self.last_time=started_at+timeout,started_at
        self.phase='ready';self.reason=None;self.verified_response=False
        self.highest={};self.observations=0
        self.response_integrity_scope=None

    def close(self, reason):
        self.phase='closed';self.reason=reason

    def tick(self, now):
        if type(now) not in (int,float) or not math.isfinite(now) or now<self.last_time:
            self.close('invalid_delivery_clock')
            raise ValueError('Finite monotonic delivery clock required')
        self.last_time=now
        if now>=self.deadline and self.phase in ('ready','awaiting_response'):
            self.phase='expired';self.reason='response_deadline_reached'
        return self.phase in ('ready','awaiting_response')

    def build_request(self, now):
        if not self.tick(now) or self.phase!='ready':
            raise ValueError('Data request already allocated or context closed')
        self.phase='awaiting_response'
        try:
            return self.sender.build_request(self.token)
        except Exception:
            self.close('request_construction_failed')
            raise

    def receive(self, frame, now):
        if not self.tick(now):return None
        self.observations+=1
        if self.observations>4096:
            self.close('receive_budget_exceeded');return None
        packet=management(frame)
        ap,sta=mac_text(self.ap),mac_text(self.station)
        if (disconnect_affects_peer(packet,ap,sta) or packet and packet['bssid']==ap
                and {packet['source'],packet['destination']}=={ap,sta}
                and packet['subtype'] in (0,2,11)):
            self.close('observed_management_boundary');return None
        if len(frame)>=24 and frame[0]&15==0 and frame[16:22]==self.ap:
            pair=(frame[4:10],frame[10:16])
            if packet is None and (pair in ((self.ap,self.station),(self.station,self.ap))
                    or pair==(bytes([255])*6,self.ap)):
                self.close('unsupported_peer_management_context');return None
        if len(frame)<24 or frame[0]&15!=8:return None
        peer=(frame[4:10],frame[10:16]) in ((self.ap,self.station),(self.station,self.ap))
        if not peer:return None
        if not frame[1]&64:
            offset=26 if frame[0]>>4==8 else 24
            if frame[offset:offset+8]==bytes.fromhex('aaaa03000000888e'):
                self.close('new_eapol_context_requires_new_session')
            return None
        try:decoded=decrypt_unicast(frame,self.tk,self.ap,self.station)
        except ValueError:return None
        if decoded['direction']!='downlink':return None
        plaintext=decoded['plaintext']
        if plaintext[:8]==bytes.fromhex('aaaa03000000888e'):
            self.close('encrypted_eapol_context_requires_new_session');return None
        priority,pn=decoded['priority'],decoded['pn']
        if pn<=self.highest.get(priority,0):return None
        self.highest[priority]=pn
        try:udp=parse_udp(plaintext)
        except ValueError:return None
        if (self.phase!='awaiting_response' or udp['source']!=['192.0.2.1',49321]
                or udp['destination']!=['192.0.2.2',51000]
                or udp['payload']!=b'WiFiSecLab-response:'+self.token):return None
        self.phase='complete';self.verified_response=True
        self.response_integrity_scope=decoded['integrity_scope']
        return {'pn':pn,'priority':priority,'udp_checksum_verified':udp['udp_checksum_verified'],
                'integrity_scope':decoded['integrity_scope'],
                'local_pn_filter_passed':True,
                'receiver_acceptance_confirmed':False}

    def report(self):
        return {'phase':self.phase,'reason':self.reason,
                'encrypted_response_observed':self.verified_response,
                'frames_observed':self.observations,
                'response_integrity_scope':self.response_integrity_scope,
                'pn_filter_scope':'Local capture-order filter for this bounded session; no AP replay verdict.',
                'ap_internal_state_confirmed':False}
