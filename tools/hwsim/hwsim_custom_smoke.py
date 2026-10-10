#!/usr/bin/env python3
"""Isolated hwsim AP and custom normal PSK client; no physical radio use."""
import argparse,hashlib,json,os,signal,subprocess,time,secrets
from pathlib import Path
from hwsim_smoke import cmd,ns


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stop-capture-after',type=float)
    args=parser.parse_args()
    if args.stop_capture_after is not None and not 0 < args.stop_capture_after <= 5:
        parser.error('Capture fault delay must be in (0,5]')
    if os.geteuid()!=0:raise SystemExit('root required')
    if Path('/sys/module/mac80211_hwsim').exists():raise SystemExit('Existing hwsim; refusing')
    names=['wslabc-ap','wslabc-sta']
    existing=cmd('ip','netns','list').split()
    if any(n in existing for n in names):raise SystemExit('Existing namespace; refusing')
    out=Path(__file__).resolve().parent/('custom-results-'+time.strftime('%Y%m%d-%H%M%S'))
    out.mkdir();owned=[];procs=[];handles=[];loaded=False;result={}
    try:
        before=set(Path('/sys/class/ieee80211').iterdir())
        cmd('modprobe','mac80211_hwsim','radios=2');loaded=True;time.sleep(.5)
        phys=sorted(set(Path('/sys/class/ieee80211').iterdir())-before)
        if len(phys)!=2:raise RuntimeError('Expected two new hwsim radios')
        for phy,name in zip(phys,names):
            if 'mac80211_hwsim' not in str((phy/'device/driver').resolve()):raise RuntimeError('Unexpected driver')
            cmd('ip','netns','add',name);owned.append(name)
            cmd('iw','phy',phy.name,'set','netns','name',name)
            ns(name,'ip','link','set','lo','up')
        interfaces=[ns(n,'iw','dev').split('Interface ')[1].split()[0] for n in names]
        apif,staif=interfaces
        apmac=ns(names[0],'cat',f'/sys/class/net/{apif}/address').strip()
        stamac=ns(names[1],'cat',f'/sys/class/net/{staif}/address').strip()
        ns(names[1],'ip','link','set',staif,'down')
        ns(names[1],'iw','dev',staif,'set','type','monitor')
        ns(names[1],'iw','dev',staif,'set','monitor','active')
        ns(names[1],'ip','link','set',staif,'up')
        ns(names[1],'iw','dev',staif,'set','channel','1')
        cmd('ip','link','set','hwsim0','up')
        ns(names[0],'ip','addr','add','192.0.2.1/30','dev',apif)
        ns(names[0],'ip','neigh','replace','192.0.2.2','lladdr',stamac,'nud','permanent','dev',apif)
        token=secrets.token_hex(16)
        conf=out/'hostapd.conf';ctrl=out/'apctrl'
        conf.write_text(f'interface={apif}\ndriver=nl80211\nctrl_interface={ctrl}\nssid=WiFiSecLab-hwsim-custom\nhw_mode=g\nchannel=1\nwpa=2\nwpa_passphrase=WiFiSecLab-test-only-2026\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nieee80211w=0\n')
        def launch(log,args):
            h=open(out/log,'w');handles.append(h)
            p=subprocess.Popen(args,stdout=h,stderr=subprocess.STDOUT);procs.append(p);return p
        cap=launch('capture.log',['tcpdump','--immediate-mode','-i','hwsim0','-U','-w',str(out/'air.pcap')])
        ap=launch('hostapd.log',['ip','netns','exec',names[0],'hostapd','-d',str(conf)])
        time.sleep(1)
        if cap.poll() is not None or ap.poll() is not None:raise RuntimeError('Producer failed')
        server=launch('udp-server.json',['ip','netns','exec',names[0],'python3',str(Path(__file__).with_name('hwsim_udp.py')),'server','--address','192.0.2.1','--token',token,'--timeout','15','--ready',str(out/'udp-ready')])
        ready_deadline=time.monotonic()+2
        while not (out/'udp-ready').exists() and server.poll() is None and time.monotonic()<ready_deadline:time.sleep(.02)
        if not (out/'udp-ready').exists():raise RuntimeError('Lab echo endpoint not ready')
        client=launch('client.json',['ip','netns','exec',names[1],'python3',str(Path(__file__).with_name('hwsim_custom_client.py')),'--capture',str(out/'air.pcap'),'--interface',staif,'--bssid',apmac,'--source',stamac,'--capture-pid',str(cap.pid),'--ap-pid',str(ap.pid),'--token',token,'--ap-namespace',names[0],'--ap-interface',apif,'--ap-control',str(ctrl)])
        if args.stop_capture_after is not None:
            time.sleep(args.stop_capture_after)
            if cap.poll() is None:
                cap.send_signal(signal.SIGINT);cap.wait(timeout=3)
        client.wait(timeout=15)
        start=time.time();snapshot=ns(names[0],'hostapd_cli','-p',str(ctrl),'-i',apif,'sta',stamac,check=False);end=time.time()
        (out/'ap-stations.txt').write_text(snapshot)
        result={'client_exit_code':client.returncode,'bssid':apmac,'station':stamac,'snapshot_started_at':start,'snapshot_finished_at':end,'authorized_snapshot':'[AUTHORIZED]' in snapshot,'physical_radios_used':False,'capture_fault_injected':args.stop_capture_after is not None,'token':token}
    finally:
        for proc in reversed(procs):
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
        for h in handles:h.close()
        for name in reversed(owned):cmd('ip','netns','del',name,check=False)
        if loaded:cmd('modprobe','-r','mac80211_hwsim',check=False)
        (out/'summary.json').write_text(json.dumps(result,indent=2))
        print('RESULT_DIR='+str(out),flush=True)
    print(json.dumps(result),flush=True)
    return 0 if result.get('client_exit_code')==0 and result.get('authorized_snapshot') else 1


if __name__=='__main__':raise SystemExit(main())
