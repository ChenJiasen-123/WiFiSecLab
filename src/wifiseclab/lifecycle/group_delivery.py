"""Caller-bound group-key delivery ledger; IEEE 802.11-2024 12.7.7.

A fixed, explicitly supplied association snapshot, not a radio client or complete
BSS state machine. An accepted response does not establish MAC installation.
"""


class GroupKeyDelivery:
    def __init__(self, bss_context, update_id, material_id, members, *, source):
        for value in (bss_context, update_id, material_id):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Explicit BSS, update and material identities required")
        if source not in ("instrumentation", "synthetic"):
            raise ValueError("Delivery state requires internal or synthetic evidence")
        if not isinstance(members, dict) or not 1 <= len(members) <= 4096:
            raise ValueError("Expected 1..4096 peer-to-association-session entries")
        for peer, session in members.items():
            if not all(isinstance(x, str) and x.strip() for x in (peer, session)):
                raise ValueError("Nonempty peer and association session required")
        self.context = bss_context
        self.update_id = update_id
        self.material_id = material_id
        self.members = dict(members)
        self.source = source
        self.sent = {peer: set() for peer in members}
        self.accepted = {}
        self.history = []
        self.findings = []

    def observe(self, kind, peer, session, counter, *, context, update_id,
                evidence, integrity_valid=False):
        if context != self.context or update_id != self.update_id:
            raise ValueError("Group update context mismatch")
        if peer not in self.members or self.members[peer] != session:
            raise ValueError("Event outside the fixed association snapshot")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("Evidence reference required")
        if type(counter) is not int or not 0 <= counter < 1 << 64:
            raise ValueError("Expected 64-bit EAPOL-Key counter")
        if kind not in ("message1_sent", "message2_accepted"):
            raise ValueError("Unsupported group delivery event")
        if kind == "message2_accepted" and integrity_valid is not True:
            raise ValueError("Accepted response requires internal integrity evidence")
        row = dict(kind=kind, peer=peer, session=session, counter=counter,
                   evidence=evidence, source=self.source)
        if kind == "message1_sent":
            if self.sent[peer] and counter <= max(self.sent[peer]):
                self.findings.append(dict(finding="non_increasing_group_message1",
                                          **row))
            self.sent[peer].add(counter)
        elif counter not in self.sent[peer]:
            self.findings.append(dict(kind="unmatched_group_message2",
                                      peer=peer, counter=counter, evidence=evidence))
        else:
            # Match any M1 in this update, not only the latest retry.
            self.accepted[peer] = row
        self.history.append(row)

    def report(self):
        pending = sorted(set(self.members) - set(self.accepted))
        return dict(bss_context=self.context, update_id=self.update_id,
                    material_id=self.material_id, source=self.source,
                    association_snapshot=dict(self.members),
                    acknowledged_members=sorted(self.accepted),
                    pending_members=pending,
                    all_snapshot_members_acknowledged=not pending,
                    findings=list(self.findings), event_history=list(self.history),
                    mac_installation_confirmed=False,
                    old_gtk_deletion_confirmed=False,
                    conformance_confirmed=False,
                    scope="Fixed caller-bound snapshot; membership changes require "
                          "a separate update decision. No cross-update replay floor, "
                          "OCV validation, timeout or hardware-state proof.")
