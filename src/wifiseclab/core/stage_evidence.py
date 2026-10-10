"""Evidence requirements for the platform's initial WPA2-PSK/CCMP scope.

Presence of an event is coverage only: it never proves a valid transition,
cryptographic verification, continuous AP state, or protocol conformance.
"""

WPA2_STAGES = (
    ('authentication', ('auth_accepted',)),
    ('association', ('assoc_accepted',)),
    ('four_way', ('handshake_started', 'handshake_message', 'handshake_completed')),
    ('authorization', ('key_installed', 'port_authorized')),
    ('protected_data', ('encrypt_new', 'data_accepted')),
    ('teardown', ('port_revoked', 'key_deleted', 'cleanup_checkpoint')),
)


def stage_evidence(history):
    """Return per-session coverage without mixing peers, runs or evidence sources.

    Multiple occurrences and their referenced evidence remain available in the
    trace. Disconnect type is a one-of condition; all other events are required.
    Fine-grained M1-M4, suites and cleanup validity are checked by other rules.
    """
    sessions = {}
    references = {}
    for index, row in enumerate(history):
        identity = (row['peer'], row['session'])
        sources = sessions.setdefault(identity, {})
        source = row.get('source', 'unknown')
        sources.setdefault(source, set()).add(row['event'])
        references.setdefault((identity, source), []).append({
            'history_index': index, 'event': row['event'],
            'evidence': row.get('evidence'),
        })
    result = []
    for (peer, session), sources in sorted(sessions.items()):
        by_source = {}
        for source, events in sorted(sources.items()):
            stages = []
            for name, required in WPA2_STAGES:
                missing = sorted(set(required) - events)
                if name == 'teardown' and not events.intersection({'disassociated', 'deauthenticated'}):
                    missing.append('disassociated_or_deauthenticated')
                relevant = set(required)
                if name == 'teardown':
                    relevant.update({'disassociated', 'deauthenticated'})
                stages.append(dict(stage=name, required_events=list(required),
                                   missing_events=missing,
                                   evidence_records=[dict(row) for row in references[((peer, session), source)]
                                                     if row['event'] in relevant],
                                   event_coverage='incomplete' if missing else 'required_event_kinds_seen'))
            by_source[source] = stages
        result.append(dict(peer=peer, session=session, evidence_sources=by_source))
    return dict(profile='initial_wpa2_psk_ccmp', sessions=result,
                ap_internal_state_confirmed=False,
                state_inference='not_performed_by_event_coverage',
                interpretation='Event-kind coverage only; no stage success or conformance verdict. '
                'Synthetic and instrumentation evidence are not combined. '
                'Rekey, PMKSA caching, FT and other profiles require separate contracts.')
