"""Offline GTK retirement obligations, IEEE 802.11-2024 12.6.19.

One caller-bound AP/BSS/role/epoch, serial GTK updates only. Material IDs are
opaque stable handles, never wire Key IDs. No radio or automatic state inference.
"""


class GtkRetirement:
    def __init__(self, bss_context, role):
        if not isinstance(bss_context, str) or not bss_context.strip():
            raise ValueError('Explicit BSS/epoch context required')
        if role not in ('ap', 'non_ap'):
            raise ValueError('Expected AP or non-AP role')
        self.context, self.role = bss_context, role
        self.active = None
        self.installed = set()
        self.pending_retirement = set()
        self.retired_materials = set()
        self.findings = []
        self.history = []
        self.checks = []
        self.observations = []

    def observe(self, kind, material_id, *, context, source, evidence, operation_completed=False):
        if context != self.context:
            raise ValueError('GTK event belongs to another BSS/epoch')
        if source not in ('instrumentation', 'synthetic', 'pcap', 'probe'):
            raise ValueError('Unknown evidence source')
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError('Evidence reference required')
        if not isinstance(material_id, str) or not material_id.strip():
            raise ValueError('Stable opaque GTK material identity required')
        if kind not in ('installed', 'encrypted_transmit', 'accepted_receive',
                        'deleted', 'checkpoint'):
            raise ValueError('Unknown GTK lifecycle event')
        row = dict(kind=kind, material_id=material_id, source=source, evidence=evidence)
        if source in ('pcap', 'probe'):
            self.observations.append(row)
            return  # Wire visibility does not establish installation or acceptance.
        if self.history and source != self.history[0]['source']:
            raise ValueError('Do not combine synthetic and instrumentation state')
        if kind in ('installed', 'deleted') and operation_completed is not True:
            raise ValueError('Key operation request alone is insufficient; completion evidence required')
        row['operation_completed'] = operation_completed
        if kind == 'installed':
            if material_id in self.retired_materials:
                self.findings.append(dict(
                    kind='previously_deleted_material_installed',
                    material_id=material_id, evidence=evidence, source=source,
                    replay_or_counter_reset_confirmed=False))
            self.installed.add(material_id)
        elif kind in ('encrypted_transmit', 'accepted_receive'):
            expected = 'encrypted_transmit' if self.role == 'ap' else 'accepted_receive'
            if kind != expected:
                raise ValueError('First-use trigger does not match the observed role')
            if material_id not in self.installed:
                raise ValueError('First use lacks correlated GTK installation')
            if material_id in self.pending_retirement:
                raise ValueError('Old GTK reuse requires a separate rollback analysis')
            if self.active is not None and self.active != material_id:
                self.pending_retirement.add(self.active)
            self.active = material_id
        elif kind == 'deleted':
            if material_id not in self.installed:
                raise ValueError('Deletion completion lacks correlated installation')
            self.retired_materials.add(material_id)
            self.installed.discard(material_id)
            self.pending_retirement.discard(material_id)
            if self.active == material_id:
                self.active = None
        else:
            # Checkpoint timing and collector completeness are caller obligations.
            self.checks.append(dict(material_id=material_id, evidence=evidence,
                deletion_required=material_id in self.pending_retirement,
                old_key_retained_at_checkpoint=material_id in self.pending_retirement
                                              and material_id in self.installed))
        self.history.append(row)

    def report(self):
        return dict(bss_context=self.context, role=self.role, active=self.active,
            installed=sorted(self.installed),
            pending_retirement=sorted(self.pending_retirement),
            previously_deleted_materials=sorted(self.retired_materials),
            findings=list(self.findings),
            checks=list(self.checks), observations=list(self.observations),
            event_history=list(self.history),
            conformance_confirmed=False,
            scope='Ordered caller-bound internal events; checkpoint completeness and '
                  'timing require independent evidence. No GTK freshness or rollback proof.')


def main(argv=None):
    """Read one bounded, ordered JSON evidence document; never collect/transmit."""
    import argparse
    import json
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        with args.trace.open('rb') as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('GTK trace exceeds 4 MiB budget')
        document = json.loads(raw.decode('utf-8-sig'))
        if not isinstance(document, dict) or set(document) != {'bss_context', 'role', 'events'}:
            raise ValueError('Expected bss_context, role and events')
        events = document['events']
        if not isinstance(events, list) or not 1 <= len(events) <= 10000:
            raise ValueError('Expected 1..10000 ordered events')
        model = GtkRetirement(document['bss_context'], document['role'])
        for index, event in enumerate(events, 1):
            try:
                if not isinstance(event, dict):
                    raise ValueError('Expected event object')
                model.observe(**event)
            except (ValueError, TypeError) as exc:
                raise ValueError(f'event {index}: {exc}') from exc
        result = json.dumps(model.report(), ensure_ascii=False, indent=2) + '\n'
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(result)
        else:
            print(result, end='')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0  # Report evidence; no conformance exit status is inferred.


if __name__ == '__main__':
    raise SystemExit(main())
