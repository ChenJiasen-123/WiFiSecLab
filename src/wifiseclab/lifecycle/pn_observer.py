"""Bounded passive PN observations for one caller-established CCMP TK context.

Only MIC-verified frames may enter. Capture order is not receiver reorder order.
No finding alone proves AP acceptance, key reinstall or a receiver replay bug.
"""
import hashlib


class PnObserver:
    def __init__(self, budget=4096):
        if type(budget) is not int or not 1 <= budget <= 100000:
            raise ValueError('Invalid PN observation budget')
        self.budget = budget
        self.seen = {}
        self.highest = {}
        self.events = []
        self.count = 0
        self.incomplete = False
        self.nonce_reuse = False

    def observe(self, index, frame, decoded):
        if decoded.get('mic_valid') is not True:
            raise ValueError('PN observations require verified MIC')
        if self.count >= self.budget:
            self.incomplete = True
            return
        self.count += 1
        # Receiver replay domains and cryptographic nonce identities differ.
        # One observer is scoped to one caller-established TK material context.
        transmitter, receiver = frame[10:16].hex(), frame[4:10].hex()
        stream = (decoded['direction'], decoded['priority'], transmitter, receiver)
        pn = decoded['pn']
        # RA is absent from the CCM nonce; do not split nonce reuse by RA.
        key = (transmitter, decoded['priority'], pn)
        offset = 26 if frame[0] >> 4 == 8 else 24
        digest = hashlib.sha256(frame[offset + 8:]).hexdigest()
        observation = None
        if key in self.seen:
            prior_index, prior_digest = self.seen[key]
            if digest == prior_digest:
                observation = 'duplicate_authenticated_ciphertext'
            else:
                observation = 'nonce_reuse_with_distinct_authenticated_ciphertext'
                self.nonce_reuse = True
        else:
            prior_index = None
            if pn <= self.highest.get(stream, 0):
                observation = 'non_increasing_pn_in_capture_order'
            self.seen[key] = (index, digest)
        self.highest[stream] = max(pn, self.highest.get(stream, 0))
        if observation:
            if len(self.events) < 256:
                self.events.append({'packet_index': index, 'previous_packet_index': prior_index,
                                    'direction': stream[0], 'priority': stream[1], 'pn': pn,
                                    'transmitter': transmitter, 'receiver': receiver,
                                    'observation': observation})
            else:
                self.incomplete = True

    def report(self):
        return {'verified_frames_observed': self.count, 'events': list(self.events),
                'distinct_authenticated_ciphertext_same_nonce_observed': self.nonce_reuse,
                'observation_incomplete': self.incomplete,
                'receiver_replay_protection_confirmed': False,
                'nonce_identity_fields': ['transmitter', 'priority', 'pn'],
                'capture_order_domain_fields': ['direction', 'priority', 'transmitter', 'receiver'],
                'key_reinstallation_confirmed': False,
                'scope': 'One known TK and the selected capture interval; capture ordering is not receiver acceptance.'}
