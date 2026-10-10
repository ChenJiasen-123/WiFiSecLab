"""Receive-driven handshake orchestration with explicit submission evidence."""
import hashlib
import math


def run_handshake(session, transport, clock, *, poll_interval=.1, max_polls=4096):
    """Use an already prepared transport; caller owns setup and cleanup.

    transport.receive(timeout) returns raw 802.11 bytes or None. It must honor
    the finite timeout. transport.submit(frame) returns the accepted byte count.
    clock is monotonic in the same domain as session.started_at. No transport
    is selected or opened here; tests supply an in-memory simulated AP.
    """
    if (type(poll_interval) not in (int, float) or not 0 < poll_interval <= 1 or
            type(max_polls) is not int or not 1 <= max_polls <= 65536):
        raise ValueError('Invalid poll interval or poll budget')
    submissions, polls, received = [], 0, 0
    stop = 'poll_budget_exhausted'
    while polls < max_polls:
        try:
            now = clock()
            active = session.tick(now)
        except (ValueError, OSError):
            stop = 'invalid_delivery_clock'
            break
        if not active:
            stop = 'session_terminal'
            break
        polls += 1
        try:
            frame = transport.receive(min(poll_interval, session.deadline - now))
        except OSError:
            stop = 'receive_error'
            break
        try:
            now = clock()
            active = session.tick(now)
        except (ValueError, OSError):
            stop = 'invalid_delivery_clock'
            break
        if not active:
            stop = 'session_terminal'
            break
        if frame is None:
            continue
        if not isinstance(frame, bytes):
            stop = 'invalid_transport_frame'
            break
        received += 1
        response = session.receive(frame, now)
        if response is None:
            continue
        # Construction can consume the rest of the deadline: never submit late.
        try:
            active = session.tick(clock())
        except (ValueError, OSError):
            stop = 'invalid_delivery_clock'
            break
        if not active:
            stop = 'deadline_before_submission'
            break
        row = {'frame_sha256': hashlib.sha256(response).hexdigest(),
               'trigger_frame_sha256': hashlib.sha256(frame).hexdigest(),
               'trigger_received_ordinal': received,
               'length': len(response), 'accepted_bytes': None,
               'submission_complete': False, 'over_air_transmission_confirmed': False}
        evidence = getattr(transport, 'last_record', None)
        if (isinstance(evidence, dict) and type(evidence.get('packet_index')) is int and
                evidence['packet_index'] > 0 and
                type(evidence.get('capture_time')) in (int, float) and
                math.isfinite(evidence['capture_time']) and evidence['capture_time'] >= 0):
            row['trigger_capture_record'] = {key: evidence[key] for key in ('packet_index', 'capture_time')}
        submissions.append(row)
        try:
            accepted = transport.submit(response)
        except OSError:
            row['result'] = 'submission_error'
            stop = 'submission_error'
            break
        if type(accepted) is int and 0 <= accepted <= len(response):
            row['accepted_bytes'] = accepted
        row['submission_complete'] = type(accepted) is int and accepted == len(response)
        row['result'] = 'submitted' if row['submission_complete'] else 'incomplete_or_unknown_submission'
        if not row['submission_complete']:
            # Do not retry an uncertain send, even if zero bytes were reported.
            stop = 'incomplete_or_unknown_submission'
            break
    if stop not in ('session_terminal', 'deadline_before_submission'):
        session.close(stop)
    return {'stop_reason': stop, 'polls': polls, 'frames_received': received,
            'submissions': submissions, 'session': session.report(),
            'over_air_transmission_confirmed': False, 'ap_authorization_confirmed': False,
            'key_installation_confirmed': False,
            'evidence_scope': 'Transport byte acceptance only; independent capture and AP state evidence required.'}
