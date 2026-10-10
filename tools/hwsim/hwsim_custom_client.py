#!/usr/bin/env python3
"""Normal custom PSK client, invoked only inside the isolated hwsim harness."""
import argparse, hashlib, json, socket, sys, time, os, select, atexit, subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from wifiseclab.network.hotspot import analyze_capture, management
from wifiseclab.core.session import run_sequence, stage_outcome
from wifiseclab.network.physical import captured_records
from wifiseclab.protocol.association_gate import admitted_session
from wifiseclab.network.capture_stream import GrowingCapture, CaptureTransport
from wifiseclab.network.handshake_runner import run_handshake
from wifiseclab.network.handshake_handoff import ClockAnchor
from wifiseclab.network.runtime_guard import RuntimeGuard
from wifiseclab.protocol.eapol import analyze_handshake
from wifiseclab.network.ccmp import derive_tk,decrypt_unicast
from wifiseclab.network.hotspot import mac_bytes
from wifiseclab.lifecycle.lab_datagram import LabCcmpUplink
from wifiseclab.lifecycle.data_session import DataSession
from wifiseclab.lifecycle.udp_evidence import parse_udp
from wifiseclab.lifecycle.predata_snapshot import collect_predata_snapshot


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--interface',required=True)
    p.add_argument('--bssid',required=True)
    p.add_argument('--source',required=True)
    p.add_argument('--capture-pid',type=int,required=True)
    p.add_argument('--ap-pid',type=int,required=True)
    p.add_argument('--token',required=True)
    p.add_argument('--ap-namespace',required=True)
    p.add_argument('--ap-interface',required=True)
    p.add_argument('--ap-control',type=Path,required=True)
    a=p.parse_args(); ssid='WiFiSecLab-hwsim-custom'
    # Fail before socket setup if this is not a simulated wireless device.
    phy=(Path('/sys/class/net')/a.interface/'phy80211').resolve()
    if 'mac80211_hwsim' not in str((phy/'device/driver').resolve()):
        raise SystemExit('Refusing non-hwsim interface')
    anchor=ClockAnchor.sample(time.monotonic,time.time)
    descriptors=[]
    atexit.register(lambda: [os.close(fd) for fd in descriptors])
    for pid in (a.capture_pid,a.ap_pid):
        if pid <= 0:raise ValueError('Invalid producer PID')
        descriptors.append(os.pidfd_open(pid))
    guard=RuntimeGuard(anchor,lambda: not select.select(descriptors,[],[],0)[0],
                       clock=time.monotonic,realtime=time.time)
    profile=None; deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        guard.check()
        try:
            profiles=analyze_capture(a.capture,ssid,a.bssid,allow_incomplete=True)['targets']
            if profiles: profile=profiles[0];break
        except (ValueError,FileNotFoundError):pass
        time.sleep(.05)
    if profile is None:raise RuntimeError('No lab AP advertisement')
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as tx:
        tx.settimeout(.5);tx.bind((a.interface,0))
        def submit(frame):
            guard.check()
            packet=bytes.fromhex('0000080000000000')+frame
            count=tx.send(packet)
            if count != len(packet):raise OSError('Partial hwsim submission')
            return len(frame)
        def exchange(kind,frame):
            submit(frame);deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                guard.check()
                r=analyze_capture(a.capture,ssid,a.bssid,frame,2,allow_incomplete=True)
                if stage_outcome(r,kind)=='success_response_observed':return r
                time.sleep(.02)
            return r
        sequence=run_sequence(ssid,a.bssid,a.source,profile,exchange)
        result={'sequence':sequence,'handshake':None}
        if sequence['association_response_confirmed']:
            guard.check()
            records=list(captured_records(a.capture,allow_incomplete=True))
            assoc=bytes.fromhex(sequence['steps'][-1]['request_hex'])
            adverts=[f for _,_,f in records if management(f) and management(f)['subtype']==8
                     and management(f)['bssid']==a.bssid]
            if not adverts:raise RuntimeError('No advertisement frame')
            guard.check()
            now=time.monotonic()
            pmk=hashlib.pbkdf2_hmac('sha1',b'WiFiSecLab-test-only-2026',ssid.encode(),4096,32)
            session=admitted_session(assoc,adverts[-1],pmk,[(anchor.convert(t),f) for _,t,f in records],now=now,window=2,timeout=4)
            response=session.admission_evidence['responses'][0]
            cursor,cutoff,_=records[response['record_index']]
            session.admission_evidence['clock_binding']={'anchor_realtime':anchor.realtime,
                'anchor_monotonic':anchor.monotonic,'anchor_uncertainty':anchor.uncertainty}
            session.admission_evidence['capture_response_record']=cursor
            with GrowingCapture(a.capture) as reader:
                transport=CaptureTransport(reader,submit,not_before=cutoff,clock=time.monotonic,sleep=time.sleep,ready=guard.check,after_record_index=cursor)
                result['handshake']=run_handshake(session,transport,time.monotonic)
                result['data_plane']={'encrypted_response_observed':False}
                if (result['handshake']['stop_reason']=='session_terminal'
                        and session.m4_responses and all(x['submission_complete'] for x in result['handshake']['submissions'])):
                    guard.check()
                    verified=analyze_handshake(a.capture,a.bssid,a.source,pmk=pmk,unwrap=True)
                    if not verified['rsne_bound_mic_verified_four_message_path_observed']:
                        raise RuntimeError('No verified lab handshake before data')
                    branch=verified['attempts'][-1]
                    m4_index=max(e['packet_index'] for e in verified['events']
                                 if e.get('message')==4 and e.get('mic_valid') is True)
                    if any(e['packet_index']>m4_index and (e.get('observation') or e.get('message') in (1,3))
                           for e in verified['events']):
                        raise RuntimeError('Context changed after verified M4')
                    def query_ap(remaining):
                        completed=subprocess.run(['ip','netns','exec',a.ap_namespace,
                            'hostapd_cli','-p',str(a.ap_control),'-i',a.ap_interface,
                            'sta',a.source],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            timeout=min(.5,remaining),check=True)
                        return completed.stdout
                    snapshot,metadata=collect_predata_snapshot(query_ap,verified,
                        hashlib.sha256(a.capture.read_bytes()).hexdigest(),
                        clock=time.monotonic,realtime=time.time,sleep=time.sleep,ready=guard.check)
                    # Persist the sample before constructing or submitting user data.
                    (a.capture.parent/'ap-predata-stations.txt').write_bytes(snapshot)
                    (a.capture.parent/'ap-predata-snapshot-metadata.json').write_text(json.dumps(metadata))
                    guard.check()
                    ap,sta=mac_bytes(a.bssid),mac_bytes(a.source)
                    tk=derive_tk(pmk,ap,sta,bytes.fromhex(branch['anonce_hex']),bytes.fromhex(branch['snonce_hex']))
                    token=bytes.fromhex(a.token)
                    data_start=time.time()
                    data_session=DataSession(tk,ap,sta,token,started_at=time.monotonic())
                    transport.not_before=data_start
                    request=data_session.build_request(time.monotonic())
                    endpoint_record={'role':'client','token':a.token,
                        'started_at':data_start,'success':False,
                        'application_payload_verified':False,
                        'local_endpoint':['192.0.2.2',51000],
                        'remote_endpoint':['192.0.2.1',49321],
                        'collector':'custom_ccmp_client'}
                    endpoint_path=a.capture.parent/'udp-client.json'
                    # Keep a failed/incomplete record if submission or receive aborts.
                    endpoint_path.write_text(json.dumps(endpoint_record))
                    submit(request)
                    result['data_plane'].update(request_sha256=hashlib.sha256(request).hexdigest(),started_at=data_start)
                    deadline=time.monotonic()+2
                    while time.monotonic()<deadline:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:break
                        received=transport.receive(min(.1,remaining))
                        if received is None:continue
                        accepted=data_session.receive(received,time.monotonic())
                        if data_session.phase in ('closed','expired'):break
                        if accepted is not None:
                            result['data_plane'].update(encrypted_response_observed=True,
                                response_sha256=hashlib.sha256(received).hexdigest(),
                                response_capture_record=transport.last_record,finished_at=time.time())
                            break
                    data_session.tick(time.monotonic())
                    result['data_plane']['session']=data_session.report()
                    endpoint_record.update(finished_at=time.time(),
                        success=data_session.verified_response,
                        application_payload_verified=data_session.verified_response)
                    endpoint_path.write_text(json.dumps(endpoint_record))
        print(json.dumps(result),flush=True)
    return 0 if (result['handshake'] and result['handshake']['session']['m4_responses_constructed']
                 and result['handshake']['stop_reason']=='session_terminal'
                 and all(row['submission_complete'] for row in result['handshake']['submissions'])
                 and result.get('data_plane',{}).get('encrypted_response_observed')) else 1


if __name__=='__main__':raise SystemExit(main())
