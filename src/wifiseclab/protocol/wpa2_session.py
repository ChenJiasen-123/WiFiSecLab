"""Bounded initial WPA2 response decisions; transport and key installation separate."""
import hashlib
import math
import secrets
from ..network.hotspot import management, disconnect_affects_peer
from wifiseclab.protocol.eapol import decode_key
from .wpa2 import build_m2, build_m4


class HandshakeSession:
    def __init__(self, association, advertisement, pmk, *, started_at=0, timeout=10,
                 response_budget=8, eapol_version=2):
        assoc = management(association)
        if assoc is None or assoc['subtype'] != 0:
            raise ValueError('Association request context required')
        if not isinstance(pmk, bytes) or len(pmk) != 32:
            raise ValueError('Single known PMK required')
        if (type(started_at) not in (int, float) or not math.isfinite(started_at) or started_at < 0 or
                type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60 or
                type(response_budget) is not int or not 1 <= response_budget <= 32 or
                type(eapol_version) is not int or eapol_version not in (1, 2, 3)):
            raise ValueError('Invalid clock, timeout, response budget or EAPOL version')
        self._association, self._advertisement, self._pmk = association, advertisement, pmk
        self.bssid, self.station = assoc['bssid'], assoc['source']
        self.deadline, self._last_time = started_at + timeout, started_at
        self.budget, self.version = response_budget, eapol_version
        self.phase, self.responses, self.events = 'waiting_m1', 0, []
        self._branches, self._anonce, self._snonce = {}, None, None
        self._authenticated_counter = None
        self.m4_responses = 0
        self._anonce_change_observed = False
        self.close_reason = None

    def _record(self, now, decision, **fields):
        self.events.append({'time': now, 'decision': decision, **fields})
        if len(self.events) > 256:
            self.events.pop(0)

    def close(self, reason):
        if self.phase not in ('closed', 'expired'):
            self.phase = 'closed'
            self.close_reason = reason
            self._branches.clear()
            self._record(self._last_time, 'local_context_closed', reason=reason)

    def tick(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < self._last_time:
            self.close('invalid_delivery_clock')
            raise ValueError('Monotonic finite session time required')
        self._last_time = now
        if now >= self.deadline and self.phase not in ('expired', 'closed'):
            self.phase = 'expired'
            self._branches.clear()
            self._record(now, 'deadline_reached_not_a_vulnerability_verdict')
        return self.phase not in ('expired', 'closed')

    def receive(self, frame, now):
        """Return at most one constructed response; this method never sends it."""
        if not self.tick(now):
            return None
        packet = management(frame)
        if (disconnect_affects_peer(packet, self.bssid, self.station) or
                packet and packet['bssid'] == self.bssid and
                {packet['source'], packet['destination']} == {self.bssid, self.station} and
                packet['subtype'] in (0, 2, 10, 11, 12)):
            self.close('management_boundary_requires_new_session')
            self._record(now, 'management_boundary_requires_new_session')
            return None
        try:
            key = decode_key(frame, self.bssid, self.station)
        except ValueError as exc:
            if getattr(exc, 'eapol_context', False):
                self.close('unsupported_eapol_context')
            self._record(now, 'unusable_frame_no_response')
            return None
        if key is None:
            return None
        message, counter = key['message'], key['replay_counter']
        if message is None:
            self.close('unknown_eapol_context_requires_new_session')
            self._record(now, 'unknown_eapol_context_requires_new_session')
            return None
        if message not in (1, 3) or key['issues']:
            self._record(now, 'unsupported_or_out_of_direction_no_response')
            return None
        if self.responses >= self.budget:
            self.close('response_budget_exhausted')
            self._record(now, 'response_budget_exhausted')
            return None
        if self._authenticated_counter is not None and counter <= self._authenticated_counter:
            self._record(now, 'counter_not_above_authenticated_history', counter=counter)
            return None
        try:
            if message == 1:
                if self.m4_responses:
                    self._record(now, 'm1_after_m4_requires_new_session')
                    return None
                changed_anonce = self._anonce is not None and key['nonce_hex'] != self._anonce
                if changed_anonce:
                    self._anonce_change_observed = True
                    # M1 is unauthenticated: replace tentative context only.
                    # Retain SNonce until authenticated completion; never join
                    # a later M3 to a discarded ANonce branch.
                if not changed_anonce and counter in self._branches:
                    self._record(now, 'duplicate_m1_counter_no_response', counter=counter)
                    return None
                snonce = self._snonce or secrets.token_bytes(32)
                response = build_m2(frame, self._association, self._pmk, snonce,
                                    sequence=self.responses, eapol_version=self.version)
                if changed_anonce:
                    self._branches.clear()
                    self._record(now, 'tentative_anonce_context_replaced')
                self._branches[counter] = (frame, response)
                self._anonce, self._snonce = key['nonce_hex'], snonce
                self.phase = 'waiting_m3'
            else:
                eligible = [value for value in self._branches if value < counter]
                if not eligible or key['nonce_hex'] != self._anonce:
                    self._record(now, 'm3_without_selected_branch')
                    return None
                m1, m2 = self._branches[max(eligible)]
                response = build_m4(m1, m2, frame, self._association, self._advertisement,
                                    self._pmk, sequence=self.responses, eapol_version=self.version)
                self._authenticated_counter = counter
                self.m4_responses += 1
                self.phase = 'm4_constructed'
        except ValueError:
            self._record(now, 'validation_failed_no_response', message=message, counter=counter)
            return None
        self.responses += 1
        self._record(now, 'response_constructed', message=message + 1, counter=counter,
                     frame_sha256=hashlib.sha256(response).hexdigest())
        return response

    def report(self):
        return {'bssid': self.bssid, 'station': self.station, 'phase': self.phase,
                'local_close_reason': self.close_reason,
                'association_admission_evidence': getattr(self, 'admission_evidence', None),
                'responses_constructed': self.responses, 'response_budget': self.budget,
                'm4_responses_constructed': self.m4_responses, 'events': list(self.events),
                'client_limitations': {
                    'initial_anonce_pinned_from_unauthenticated_m1': False,
                    'different_anonce_m1_observed': self._anonce_change_observed,
                    'different_anonce_recovery_supported': True,
                    'ap_fault_inferred_from_anonce_change': False},
                'transmitted': False, 'key_installation_performed': False,
                'ap_authorization_confirmed': False,
                'scope': 'Initial PSK/CCMP response decisions only; association acceptance, transport, installation, data validation and rekey require separate evidence.'}
