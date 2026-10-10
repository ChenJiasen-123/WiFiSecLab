#!/usr/bin/env python3
"""Run normal connections on isolated simulated radios. Requires root on Linux."""
import json, os, subprocess, time, signal, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wifiseclab.lifecycle.lifecycle import Lifecycle, Stage
from wifiseclab.network.kernel_trace import KernelTrace
from wifiseclab.lifecycle.key_evidence import analyze

def cmd(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check).stdout

def ns(name, *args, check=True):
    return cmd("ip", "netns", "exec", name, *args, check=check)

def main():
    if os.geteuid() != 0:
        raise SystemExit("root required")
    if Path("/sys/module/mac80211_hwsim").exists():
        raise SystemExit("Existing hwsim detected: refusing to change another experiment")
    out = Path(__file__).resolve().parents[2] / "reports" / ("lifecycle-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    out.mkdir(parents=True)
    namespaces = ["wslab-ap", "wslab-sta"]
    for name in namespaces:
        if name in cmd("ip", "netns", "list").split():
            raise SystemExit("Namespace already exists: " + name)
    results, processes, handles = [], [], []
    traces = []
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
        (out / "environment.txt").write_text(cmd("uname", "-a") + cmd("hostapd", "-v", check=False) + cmd("wpa_supplicant", "-v", check=False))
        profiles = [("wpa2", "WPA-PSK", "WPA-PSK", 0), ("wpa3", "SAE", "SAE", 2),
                    ("transition-psk", "WPA-PSK SAE", "WPA-PSK", 1),
                    ("transition-sae", "WPA-PSK SAE", "SAE", 1)]
        for label, apakm, staakm, pmf in profiles:
            case = out / label
            case.mkdir()
            trace = KernelTrace(case, f"wifiseclab-{os.getpid()}-{label}")
            traces.append(trace)
            trace.start()
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
            action_log = []
            peer = ns(namespaces[1], "cat", f"/sys/class/net/{staif}/address").strip()
            bssid = ns(namespaces[0], "cat", f"/sys/class/net/{apif}/address").strip()
            controller = Lifecycle(label, "SAE" if staakm == "SAE" else "WPA2-PSK",
                                   bssid=bssid, station=peer)
            controller.action("connect", "supplicant.log:process-start")
            def await_stage(expected, phase):
                deadline = time.monotonic() + 12
                for number in range(100):
                    status = ns(namespaces[1], "wpa_cli", "-p", stactrl, "-i", staif, "status", check=False)
                    apstatus = ns(namespaces[0], "hostapd_cli", "-p", apctrl, "-i", apif, "sta", peer, check=False)
                    ref = f"{phase}-{number:03d}"
                    (case / (ref + "-sta.txt")).write_text(status)
                    (case / (ref + "-ap.txt")).write_text(apstatus)
                    controller.observe(status, apstatus, peer, ref)
                    if controller.stage == expected:
                        trace.checkpoint(phase, phys[0].name)
                        return True
                    if time.monotonic() > deadline or ap.poll() is not None or sta.poll() is not None:
                        controller.timeout(ref)
                        return False
                    time.sleep(0.2)
                controller.timeout(phase)
                return False
            if await_stage(Stage.CONNECTED, "connect"):
                controller.action("disconnect", "actions.json:disconnect")
                response = ns(namespaces[1], "wpa_cli", "-p", stactrl, "-i", staif, "disconnect", check=False)
                action_log.append(dict(action="disconnect", response=response, monotonic=time.monotonic()))
                if response.strip() != "OK":
                    controller.timeout("actions.json:disconnect-rejected")
                elif await_stage(Stage.DISCONNECTED, "disconnect"):
                    controller.action("reconnect", "actions.json:reconnect")
                    response = ns(namespaces[1], "wpa_cli", "-p", stactrl, "-i", staif, "reconnect", check=False)
                    action_log.append(dict(action="reconnect", response=response, monotonic=time.monotonic()))
                    if response.strip() != "OK":
                        controller.timeout("actions.json:reconnect-rejected")
                    else:
                        await_stage(Stage.DONE, "reconnect")
            result = controller.report()
            (case / "actions.json").write_text(json.dumps(action_log, indent=2))
            (case / "model-report.json").write_text(json.dumps(result, indent=2))
            results.append(result)
            print(json.dumps(dict(profile=label, passed=result["passed"], stage=result["stage"])), flush=True)
            for proc in (sta, ap, cap):
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try: proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait()
            trace.stop()
            key_report = analyze((case / "kernel-trace.txt").read_text(), phys[0].name, peer,
                                 json.loads((case / "trace-stats.json").read_text()))
            (case / "key-report.json").write_text(json.dumps(key_report, indent=2))
            time.sleep(0.3)
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
        for trace in traces:
            if trace.active: trace.stop()
        for h in handles: h.close()
        for name in namespaces:
            cmd("ip", "netns", "del", name, check=False)
        if loaded:
            cmd("modprobe", "-r", "mac80211_hwsim", check=False)
        (out / "summary.json").write_text(json.dumps(results, indent=2))
        print("RESULT_DIR=" + str(out), flush=True)
    return 0 if len(results) == 4 and all(r["passed"] for r in results) else 1

if __name__ == "__main__":
    raise SystemExit(main())
