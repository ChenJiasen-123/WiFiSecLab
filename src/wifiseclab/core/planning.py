"""Offline, reviewable WPA2 platform plans; no sockets or client execution."""
import argparse
import hashlib
import json
from pathlib import Path
from ..network.hotspot import build_request, mac_bytes, mac_text, elements, rsn_details
from wifiseclab.core.session import build_association
from wifiseclab.core.stage_evidence import WPA2_STAGES


def build_wpa2_plan(ssid, bssid, station, profile, session_id):
    if not isinstance(profile, dict):
        raise ValueError('Expected an AP profile object')
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError('Expected an explicit session ID')
    ap, sta = mac_text(mac_bytes(bssid)), mac_text(mac_bytes(station))
    # Validate the whole association profile before returning any plan.
    association = build_association(ssid, ap, sta, profile)
    authentication = build_request('auth', ssid, ap, sta)
    requested_rsne = elements(association[28:])[48]
    advertised_policy = {key: profile.get(key) for key in
        ('rsn_hex', 'group_cipher', 'pairwise_ciphers', 'akm_suites',
         'pmf_capable', 'pmf_required', 'rsn_defaulted_fields')}
    policy_bytes = json.dumps(advertised_policy, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
    security_context = dict(advertised=advertised_policy,
        advertised_policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        requested=rsn_details(requested_rsne), negotiation_confirmed=False,
        evidence_binding='Input profile only; original capture binding required at runtime.',
        second_m3_rsne='May be legal; unsupported by the baseline execution path, not a violation by itself.')
    frames = {}
    for name, raw in (('authentication', authentication), ('association', association)):
        frames[name] = dict(format='raw-80211-without-radiotap-or-fcs',
                            frame_hex=raw.hex(), frame_sha256=hashlib.sha256(raw).hexdigest())
    stages = []
    previous = None
    for name, events in WPA2_STAGES:
        stage = dict(stage=name, after=previous, required_internal_events=list(events),
                     execution_status='not_executed')
        stage['state_evidence_contract'] = {
            'entry_state': 'unproven_until_runtime_evidence',
            'predecessor_plan_is_entry_state_proof': False,
            'required_bindings': ['test_case_id', 'association_epoch',
                                  'input_sequence_hash', 'observation_window'],
            'response_classes': ['expected', 'unexpected', 'unknown'],
            'timeout_alone_proves_state_transition': False,
            'elapsed_time_is_code_coverage': False,
            'reset': 'Require scoped reset evidence before combining independent cases; a reset request alone is insufficient.',
            'implementation_status': 'contract_only_executor_not_attached',
        }
        if name in frames:
            stage['prepared_frame'] = frames[name]
        else:
            stage['construction'] = 'runtime_context_required'
        if name == 'four_way':
            stage['runtime_inputs'] = ['verified_association_context', 'bound_advertisement',
                                       'current_m1', 'pmk_handle', 'fresh_snonce',
                                       'current_m3_with_verified_mic_and_rsne']
        if name == 'protected_data':
            stage['runtime_inputs'] = ['current_tk_handle', 'nonce_domain', 'fresh_pn',
                                       'payload', 'receiver_evidence']
            stage['evidence_requirements'] = {
                'integrity': 'Verified MIC over the selected cipher layout and canonical AAD.',
                'context': ['association_epoch', 'tk_material_context', 'transmitter',
                            'receiver', 'tid_or_non_qos_zero'],
                'acceptance': 'Correlated delivery or trusted receiver state; ACK alone is insufficient.',
                'ordering': 'Capture order does not establish receiver reorder or replay decisions.',
            }
            stage['duplicate_detection_contract'] = {
                'reference': 'IEEE 802.11-2024 10.3.2.14 / Table 10-6',
                'mac_duplicate_filter': 'Receiver cache domain and Retry rules; not cipher replay.',
                'cipher_replay_filter': 'Selected SA/TID PN rules after applicable reordering.',
                'capture_duplicates': 'Preserve records; identical observations do not prove receiver delivery.',
                'qos_null_and_ba': 'Require their own applicable rules; do not apply RC2 blindly.',
                'receiver_cache_model_implemented': False,
                'ba_context_required': ['agreement_identity', 'addba_request_response_binding',
                    'negotiated_window_size', 'sequence_modulus', 'sar_mode',
                    'protected_ba_mode', 'agreement_lifetime'],
                'ba_reordering_model_implemented': False,
            }
            stage['fragmentation_coverage'] = {
                'status': 'not_implemented',
                'references': ['IEEE 802.11-2024 10.4', '10.5', '12.5.2.4.4'],
                'required_invariants': [
                    'same_key_material_and_protection_context',
                    'same_sender_destination_sequence_and_tid_context',
                    'ordered_fragment_numbers_and_consecutive_pn',
                    'consistent_msdu_or_amsdu_interpretation',
                    'bounded_receive_lifetime_and_duplicate_discard',
                ],
                'ack_is_acceptance_evidence': False,
            }
        if name == 'teardown':
            stage['required_one_of'] = ['disassociated', 'deauthenticated']
        stages.append(stage)
        previous = name
    return dict(schema_version=1, profile='initial_wpa2_psk_ccmp', session=session_id,
                identity=dict(bssid=ap, station=sta, ssid=ssid), stages=stages,
                security_context=security_context,
                oracle_contract={
                    'standard_revision': 'IEEE 802.11-2024',
                    'supported_profile': 'initial_wpa2_psk_ccmp',
                    'configuration_evidence': 'input_advertisement_only_not_internal_ap_configuration',
                    'unknown_preconditions': 'Keep verdict unknown until required capability and configuration evidence is bound.',
                    'unexpected_response': 'Candidate deviation requiring trace review and root-cause analysis.',
                    'unsupported_response_is_violation': False,
                    'wire_silence_proves_crash': False,
                    'implementation_status': 'contract_only_no_automatic_classifier',
                },
                transmitted=False, ap_state_confirmed=False,
                limitations=['Plan only; no automatic executor is attached.',
                    'Stage dependencies express planning order, not proven transitions.',
                    'Wire responses and internal acceptance require separate evidence.',
                    'PMF-required, FT, SAE, rekey and cached-PMK flows are outside this plan.',
                    'No secrets are embedded; runtime key handles must be supplied separately.'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ssid', 'bssid', 'station', 'session'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ap-profile', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        profile = json.loads(args.ap_profile.read_text(encoding='utf-8-sig'))
        plan = build_wpa2_plan(args.ssid, args.bssid, args.station, profile, args.session)
        serialized = json.dumps(plan, ensure_ascii=False, indent=2) + '\n'
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(serialized)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
