"""Formal hotspot discovery, request construction and independent observation."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from wifiseclab.network.hotspot import analyze_capture, build_request, mac_bytes, mac_text, ssid_bytes, management, elements
from wifiseclab.network.network_guard import NetworkGuard
from wifiseclab.network.physical import PhysicalRadioAdapter, captured_records
from wifiseclab.network.radio_roles import RadioRoles, discover
from ..core.session import run_sequence, stage_outcome
from ..protocol.eapol import analyze_handshake
from wifiseclab.network.handshake_handoff import ClockAnchor, prepare_handoff
from wifiseclab.network.handshake_runner import run_handshake


def selected_advertisement(path, ssid, bssid):
    selected = None
    for _, _, frame in captured_records(path, allow_incomplete=True):
        packet = management(frame)
        if not packet or packet['subtype'] != 8 or (packet['source'], packet['bssid'], packet['destination']) != (
                bssid, bssid, 'ff:ff:ff:ff:ff:ff'):
            continue
        selected = None
        try:
            if len(packet['body']) < 12:
                continue
            ies = elements(packet['body'][12:])
            if ies.get(0) == ssid_bytes(ssid) and 48 in ies and 244 not in ies:
                selected = frame
        except ValueError:
            pass
    if selected is None:
        raise ValueError('No current baseline AP beacon available for handshake binding')
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build', help='Construct a request offline; never transmit')
    build.add_argument('--kind', choices=('auth', 'probe'), required=True)
    analyze = sub.add_parser('analyze', help='Analyze an existing pcap offline')
    analyze.add_argument('--pcap', type=Path, required=True)
    analyze.add_argument('--request', type=Path)
    analyze.add_argument('--window', type=float, default=4)
    live = []
    for name in ('discover', 'probe', 'auth', 'associate', 'handshake'):
        command = sub.add_parser(name)
        command.add_argument('--output', type=Path, required=True, help='New evidence directory')
        command.add_argument('--duration', type=float, default=2 if name == 'discover' else 4)
        if name == 'discover':
            command.add_argument('--channels', type=int, nargs='+', default=list(range(1, 12)))
            command.add_argument('--bssid')
        else:
            command.add_argument('--channel', type=int, required=True)
            command.add_argument('--bssid', required=True)
            command.add_argument('--source')
        live.append(command)
        if name == 'handshake':
            command.add_argument('--pmk-file', type=Path, required=True, help='Exactly 32 raw bytes of one known PMK')
    for command in (build, analyze, *live):
        command.add_argument('--ssid', required=True)
    build.add_argument('--bssid', required=True)
    build.add_argument('--source')
    build.add_argument('--output', type=Path, required=True)
    analyze.add_argument('--bssid')
    args = parser.parse_args(argv)
    try:
        pmk = None
        if args.command == 'handshake':
            pmk = args.pmk_file.read_bytes()
            if len(pmk) != 32:
                raise ValueError('PMK file must contain exactly 32 raw bytes')
            try:
                from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
            except ImportError as exc:
                raise ValueError('Handshake requires the optional crypto extra') from exc
        ssid_bytes(args.ssid)
        if args.bssid:
            mac_bytes(args.bssid)
        if args.command == 'build':
            frame = build_request(args.kind, args.ssid, args.bssid, args.source)
            args.output.mkdir(parents=True, exist_ok=False)
            (args.output / 'request.bin').write_bytes(frame)
            result = {'kind': args.kind, 'ssid': args.ssid, 'bssid': args.bssid,
                      'source': mac_text(frame[10:16]), 'frame_hex': frame.hex(),
                      'transmitted': False, 'radiotap_included': False, 'fcs_included': False}
            (args.output / 'request.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == 'analyze':
            result = analyze_capture(args.pcap, args.ssid, args.bssid,
                                     args.request.read_bytes() if args.request else None, args.window)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError('Live hotspot commands require root on Linux')
        if not 0 < args.duration <= 30:
            raise ValueError('duration must be 0..30 seconds, excluding zero')
        if args.output.exists():
            raise ValueError('Evidence directory already exists; choose a new --output')
        channels = args.channels if args.command == 'discover' else [args.channel]
        radios = discover()
        roles = [RadioRoles.bind(radios, channel) for channel in channels]
        frame = None if args.command == 'discover' else build_request(
            'auth' if args.command in ('associate', 'handshake') else args.command, args.ssid, args.bssid, args.source)
        adapter = PhysicalRadioAdapter(roles[0], args.output)
        guard = NetworkGuard([roles[0].injector.interface, roles[0].listener.interface])
        def interrupted(signum, stack):
            raise KeyboardInterrupt
        old_handler = signal.signal(signal.SIGTERM, interrupted)
        preflight = None
        sequence = None
        handshake = None
        error = None
        try:
            with guard:
                with adapter:
                    if frame is None:
                        for channel in channels:
                            for interface in adapter.interfaces.values():
                                adapter.command('iw', 'dev', interface, 'set', 'channel', str(channel))
                            time.sleep(args.duration)
                    else:
                        (args.output / 'request.bin').write_bytes(frame)
                        time.sleep(2)
                        before = analyze_capture(args.output / 'air.pcap', args.ssid, args.bssid, allow_incomplete=True)
                        candidates = [row for row in before['targets'] if row['beacons'] and row.get('channel') == args.channel]
                        preflight = bool(candidates)
                        if args.command in ('auth', 'associate', 'handshake'):
                            preflight = preflight and any('000fac02' in row.get('akm_suites', []) and
                                                        not row.get('rsn_parse_error') for row in candidates)
                        if preflight:
                            if args.command in ('associate', 'handshake'):
                                advertisement = selected_advertisement(args.output / 'air.pcap', args.ssid,
                                    mac_text(mac_bytes(args.bssid))) if args.command == 'handshake' else None
                                anchor = ClockAnchor.sample(time.monotonic, time.time) if args.command == 'handshake' else None
                                def exchange(kind, request):
                                    (args.output / (kind + '-request.bin')).write_bytes(request)
                                    adapter.send(request)
                                    if args.command != 'handshake':
                                        time.sleep(args.duration)
                                        return analyze_capture(args.output / 'air.pcap', args.ssid, args.bssid,
                                                               request, args.duration, allow_incomplete=True)
                                    deadline = time.monotonic() + args.duration
                                    while True:
                                        if adapter.capture is None or adapter.capture.poll() is not None:
                                            raise OSError('Independent capture exited during association sequence')
                                        observed = analyze_capture(args.output / 'air.pcap', args.ssid, args.bssid,
                                                                   request, args.duration, allow_incomplete=True)
                                        if stage_outcome(observed, kind) != 'unknown_no_response' and observed.get('request_observed'):
                                            return observed
                                        remaining = deadline - time.monotonic()
                                        if remaining <= 0:
                                            return observed
                                        time.sleep(min(.05, remaining))
                                sequence = run_sequence(args.ssid, args.bssid, mac_text(frame[10:16]),
                                                        candidates[0], exchange)
                                if args.command == 'handshake' and sequence['association_response_confirmed']:
                                    association = bytes.fromhex(sequence['steps'][-1]['request_hex'])
                                    session, bridge = prepare_handoff(adapter, association, advertisement, pmk, anchor,
                                        window=min(args.duration, 10), timeout=args.duration,
                                        clock=time.monotonic, realtime=time.time, sleep=time.sleep)
                                    with bridge:
                                        handshake = run_handshake(session, bridge, time.monotonic)
                            else:
                                adapter.send(frame)
                                time.sleep(args.duration)
        except BaseException as exc:
            error = f'{type(exc).__name__}: {exc}'
        finally:
            signal.signal(signal.SIGTERM, old_handler)
        if not adapter.output_created:
            raise RuntimeError((error or 'Experiment did not start') +
                               ('; restore errors: ' + '; '.join(guard.cleanup_errors) if guard.cleanup_errors else ''))
        transport = adapter.report()
        try:
            result = analyze_capture(args.output / 'air.pcap', args.ssid, args.bssid, frame, args.duration)
        except (OSError, ValueError) as exc:
            result = {'analysis_error': str(exc)}
        result.update(command=args.command, channels=channels, preflight_confirmed=preflight,
                      submitted_frames=len(adapter.actions), error=error,
                      capture_error=transport['capture_error'], capture_exit_code=transport['capture_exit_code'],
                      cleanup_errors=transport['cleanup_errors'] + guard.cleanup_errors)
        if args.command == 'handshake':
            result['handshake'] = handshake
            result['success_criterion'] = 'Constructed/submitted M4 and finalized RSNE-bound MIC-verified capture path; AP authorization and encrypted data connectivity are not established.'
        if sequence is not None and not result.get('analysis_error'):
            # Recheck each stage against the finalized, strictly parsed capture.
            for step in sequence['steps']:
                final = analyze_capture(args.output / 'air.pcap', args.ssid, args.bssid,
                                        bytes.fromhex(step['request_hex']), args.duration)
                step['final_evidence'] = final
                step['outcome'] = stage_outcome(final, step['kind'])
            sequence['association_response_confirmed'] = (len(sequence['steps']) == 2 and
                all(step['outcome'] == 'success_response_observed' for step in sequence['steps']))
            result['sequence'] = sequence
            result['eapol'] = analyze_handshake(args.output / 'air.pcap', args.bssid, sequence['source'],
                                               pmk=pmk, unwrap=pmk is not None)
        (args.output / 'hotspot-report.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if error or result.get('analysis_error') or result['capture_error'] or result['cleanup_errors'] or result['capture_exit_code'] != 0:
            return 2
        if frame is None:
            return 0 if result.get('targets') else 1
        if args.command == 'handshake':
            return 0 if (sequence and sequence['association_response_confirmed'] and handshake and
                handshake['session']['m4_responses_constructed'] > 0 and
                handshake['stop_reason'] == 'session_terminal' and
                all(row['submission_complete'] for row in handshake['submissions']) and
                result.get('eapol', {}).get('rsne_bound_mic_verified_four_message_path_observed')) else 1
        if args.command == 'associate':
            return 0 if sequence and sequence['association_response_confirmed'] else 1
        if args.command == 'auth':
            return 0 if result.get('authentication_success_response_observed') else 1
        return 0 if result.get('response_observed') else 1
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())
