#!/usr/bin/env python3
"""Run normal connections on isolated simulated radios. Requires root on Linux."""
import json, os, subprocess, time, signal, hashlib, secrets
from pathlib import Path

def cmd(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check).stdout

def ns(name, *args, check=True):
    return cmd("ip", "netns", "exec", name, *args, check=check)

def main():
    if os.geteuid() != 0:
        raise SystemExit("root required")
    if Path("/sys/module/mac80211_hwsim").exists():
        raise SystemExit("Existing hwsim detected: refusing to change another experiment")
    out = Path(__file__).resolve().parent / ("hwsim-results-" + time.strftime("%Y%m%d-%H%M%S"))
    out.mkdir()
    namespaces = ["wslab-ap", "wslab-sta"]
    for name in namespaces:
        if name in cmd("ip", "netns", "list").split():
            raise SystemExit("Namespace already exists: " + name)
    results, processes, handles = [], [], []
    loaded = False
    try:
        before = set(Path("/sys/class/ieee80211").iterdir())
        cmd("modprobe", "mac80211_hwsim", "radios=2")
        loaded = True
        time.sleep(1)
        phys = sorted(set(Path("/sys/class/ieee80211").iterdir()) - before)
        if len(phys) != 2:
            raise RuntimeError("expected exactly two new simulated radios")
        for phy, name in zip(phys, namespaces):
            cmd("ip", "netns", "add", name)
            cmd("iw", "phy", phy.name, "set", "netns", "name", name)
            ns(name, "ip", "link", "set", "lo", "up")
        cmd("ip", "link", "set", "hwsim0", "up")
        apif = ns(namespaces[0], "iw", "dev").split("Interface ")[1].split()[0]
        staif = ns(namespaces[1], "iw", "dev").split("Interface ")[1].split()[0]
        ns(namespaces[0], 'ip', 'addr', 'add', '192.0.2.1/30', 'dev', apif)
        ns(namespaces[1], 'ip', 'addr', 'add', '192.0.2.2/30', 'dev', staif)
        (out / "environment.txt").write_text(cmd("uname", "-a") + cmd("hostapd", "-v", check=False) + cmd("wpa_supplicant", "-v", check=False))
        profiles = [("wpa2", "WPA-PSK", "WPA-PSK", 0), ("wpa3", "SAE", "SAE", 2),
                    ("transition-psk", "WPA-PSK SAE", "WPA-PSK", 1),
                    ("transition-sae", "WPA-PSK SAE", "SAE", 1)]
        for label, apakm, staakm, pmf in profiles:
            case = out / label
            case.mkdir()
            apctrl, stactrl = str(case / "apctrl"), str(case / "stactrl")
            password = "WiFiSecLab-test-only-2026"
            apconf = f"interface={apif}\ndriver=nl80211\nctrl_interface={apctrl}\nssid=WiFiSecLab-hwsim\nhw_mode=g\nchannel=1\nwpa=2\nwpa_passphrase={password}\nwpa_key_mgmt={apakm}\nrsn_pairwise=CCMP\nieee80211w={pmf}\n"
            if "SAE" in apakm:
                apconf += "sae_groups=19\n"
            staconf = f'ctrl_interface={stactrl}\nnetwork={{\n ssid="WiFiSecLab-hwsim"\n psk="{password}"\n key_mgmt={staakm}\n ieee80211w={2 if staakm == "SAE" else 0}\n scan_freq=2412\n}}\n'
            (case / "hostapd.conf").write_text(apconf)
            (case / "supplicant.conf").write_text(staconf)
            def launch(name, logfile, *args):
                handle = open(case / logfile, "w")
                handles.append(handle)
                proc = subprocess.Popen(["ip", "netns", "exec", name, *args], stdout=handle, stderr=subprocess.STDOUT)
                processes.append(proc)
                return proc
            capture_handle = open(case / "capture.log", "w")
            handles.append(capture_handle)
            cap = subprocess.Popen(["tcpdump", "--immediate-mode", "-i", "hwsim0", "-U", "-w", str(case / "air.pcap")], stdout=capture_handle, stderr=subprocess.STDOUT)
            processes.append(cap)
            ap = launch(namespaces[0], "hostapd.log", "hostapd", "-d", str(case / "hostapd.conf"))
            time.sleep(1)
            sta = launch(namespaces[1], "supplicant.log", "wpa_supplicant", "-d", "-Dnl80211", "-i", staif, "-c", str(case / "supplicant.conf"))
            status = ""
            for attempt in range(20):
                time.sleep(0.5)
                status = ns(namespaces[1], "wpa_cli", "-p", stactrl, "-i", staif, "status", check=False)
                if "wpa_state=COMPLETED" in status or ap.poll() is not None or sta.poll() is not None:
                    break
            peer = ns(namespaces[1], "cat", f"/sys/class/net/{staif}/address").strip()
            bssid = ns(namespaces[0], "cat", f"/sys/class/net/{apif}/address").strip()
            snapshot_start = time.time()
            apstatus = ns(namespaces[0], "hostapd_cli", "-p", apctrl, "-i", apif, "sta", peer, check=False)
            snapshot_end = time.time()
            (case / "sta-status.txt").write_text(status)
            snapshot_bytes = apstatus.encode('utf-8')
            (case / "ap-stations.txt").write_bytes(snapshot_bytes)
            ok = "wpa_state=COMPLETED" in status and "[AUTHORIZED]" in apstatus
            result = {"profile": label, "connected": ok, "sta_status": status, "ap_station_status": apstatus}
            data = {'success': False, 'status': 'not_run_connection_failed'}
            if ok:
                helper = str(Path(__file__).with_name('hwsim_udp.py'))
                token = secrets.token_hex(16)
                ready = case / 'udp-ready'
                server = launch(namespaces[0], 'udp-server.json', 'python3', helper,
                                'server', '--address', '192.0.2.1', '--token', token,
                                '--ready', str(ready))
                deadline = time.monotonic() + 2
                while not ready.exists() and server.poll() is None and time.monotonic() < deadline:
                    time.sleep(.02)
                if ready.exists():
                    client_text = ns(namespaces[1], 'python3', helper, 'client',
                                     '--address', '192.0.2.1', '--token', token, check=False)
                    (case / 'udp-client.json').write_text(client_text)
                    server.wait(timeout=4)
                    client_report = json.loads(client_text)
                    server_report = json.loads((case / 'udp-server.json').read_text())
                    data = {'success': bool(client_report['success'] and server_report['success']),
                            'status': 'observed_exchange', 'token': token,
                            'client': client_report, 'server': server_report,
                            'scope': 'Normal endpoint UDP round trip; no isolation or key-installation claim'}
                else:
                    data = {'success': False, 'status': 'server_not_ready'}
            (case / 'data-plane.json').write_text(json.dumps(data, indent=2))
            result['data_plane'] = data
            results.append(result)
            print(json.dumps(result), flush=True)
            for proc in (sta, ap, cap):
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try: proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait()
            (case / 'ap-snapshot-metadata.json').write_text(json.dumps({
                'source': 'hostapd_ctrl', 'clock': 'pcap-realtime-same-host',
                'bssid': bssid, 'station': peer,
                'started_at': snapshot_start, 'finished_at': snapshot_end,
                'snapshot_sha256': hashlib.sha256(snapshot_bytes).hexdigest(),
                'pcap_sha256': hashlib.sha256((case / 'air.pcap').read_bytes()).hexdigest()
            }, indent=2), encoding='utf-8')
            if data.get('status') == 'observed_exchange':
                (case / 'data-metadata.json').write_text(json.dumps({
                    'source': 'hwsim_endpoint_collector', 'clock': 'pcap-realtime-same-host',
                    'bssid': bssid, 'station': peer,
                    'ap_namespace': namespaces[0], 'sta_namespace': namespaces[1],
                    'ap_interface': apif, 'sta_interface': staif,
                    'ap_ipv4': '192.0.2.1', 'station_ipv4': '192.0.2.2',
                    'client_sha256': hashlib.sha256((case / 'udp-client.json').read_bytes()).hexdigest(),
                    'server_sha256': hashlib.sha256((case / 'udp-server.json').read_bytes()).hexdigest(),
                    'pcap_sha256': hashlib.sha256((case / 'air.pcap').read_bytes()).hexdigest()
                }, indent=2), encoding='utf-8')
            time.sleep(0.3)
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
        for h in handles: h.close()
        for name in namespaces:
            cmd("ip", "netns", "del", name, check=False)
        if loaded:
            cmd("modprobe", "-r", "mac80211_hwsim", check=False)
        (out / "summary.json").write_text(json.dumps(results, indent=2))
        print("RESULT_DIR=" + str(out), flush=True)
    return 0 if len(results) == 4 and all(r["connected"] and r["data_plane"]["success"] for r in results) else 1

if __name__ == "__main__":
    raise SystemExit(main())
