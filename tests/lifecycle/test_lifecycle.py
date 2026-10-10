import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wifiseclab.lifecycle.lifecycle import Lifecycle, Stage
PEER = "02:00:00:00:00:01"
BSSID = "02:00:00:00:00:aa"
STA = "bssid="+BSSID+"\naddress="+PEER+"\npairwise_cipher=CCMP\ngroup_cipher=CCMP\nwpa_state=COMPLETED\nkey_mgmt=WPA2-PSK\n"
AP = PEER + "\nflags=[AUTH][ASSOC][AUTHORIZED]\n"
class LifecycleTests(unittest.TestCase):
    def test_full_cycle(self):
        m=Lifecycle("wpa2", "WPA2-PSK",bssid=BSSID,station=PEER)
        m.action("connect","start")
        self.assertTrue(m.observe(STA,AP,PEER,"connected"))
        m.action("disconnect","command")
        self.assertFalse(m.observe("address="+PEER+"\nwpa_state=DISCONNECTED", AP, PEER,"still-authorized"))
        self.assertTrue(m.observe("address="+PEER+"\nwpa_state=DISCONNECTED", "FAIL", PEER,"removed"))
        m.action("reconnect","command")
        m.observe(STA,AP,PEER,"new-connection")
        self.assertTrue(m.report()["passed"])
        self.assertEqual(m.session,2)
        self.assertTrue(m.report()["unverified"])
    def test_connection_error_not_station_removed(self):
        m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER);m.action("connect","s");m.observe(STA,AP,PEER,"c");m.action("disconnect","d")
        m.observe("address="+PEER+"\nwpa_state=DISCONNECTED","Could not connect to hostapd",PEER,"e")
        self.assertEqual(m.stage,Stage.DISCONNECTING)
    def test_wrong_peer_does_not_confirm(self):
        m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER);m.action("connect","s")
        m.observe(STA,AP,"02:00:00:00:00:02","e")
        self.assertEqual(m.stage,Stage.CONNECTING)
    def test_sae_requires_mfp(self):
        m=Lifecycle("wpa3","SAE",bssid=BSSID,station=PEER);m.action("connect","s")
        sta="bssid="+BSSID+"\naddress="+PEER+"\npairwise_cipher=CCMP\ngroup_cipher=CCMP\nwpa_state=COMPLETED\nkey_mgmt=SAE\npmf=2"
        m.observe(sta,AP,PEER,"e")
        self.assertEqual(m.stage,Stage.CONNECTING)
        m.observe(sta,AP.replace("[AUTH]","[AUTH][MFP]"),PEER,"e2")
        self.assertEqual(m.stage,Stage.CONNECTED)
    def test_action_guard(self):
        with self.assertRaises(ValueError): Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER).action("reconnect","e")
    def test_timeout_not_pass(self):
        m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER);m.action("connect","s");m.timeout("deadline")
        self.assertFalse(m.report()["passed"])
        self.assertEqual(m.findings[0]["code"],"LIFECYCLE_TIMEOUT")

    def test_duplicate_station_status_never_advances(self):
        for extra in ("wpa_state=DISCONNECTED\n", "wpa_state=COMPLETED\n",
                      "key_mgmt=WPA2-PSK\n"):
            m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER);m.action("connect","start")
            self.assertFalse(m.observe(STA+extra,AP,PEER,"duplicate"))
            self.assertEqual(m.stage,Stage.CONNECTING)
            self.assertFalse(m.timeline[-1]["facts"]["sta_response_valid"])
            self.assertTrue(m.observe(STA,AP,PEER,"valid-later"))

    def test_invalid_ap_flags_never_confirm_connect_or_disconnect(self):
        for ap in (AP+"flags=\n", AP+"flags=[AUTH][ASSOC][AUTHORIZED]\n",
                   PEER+"\nflags=garbage[AUTH][ASSOC][AUTHORIZED]\n",
                   PEER+"\nflags=[AUTH][ASSOC][AUTHORIZED]garbage\n",
                   PEER+"\nflags=[AUTH][ASSOC][AUTHORIZED\n", PEER+"\n"):
            m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER);m.action("connect","start")
            self.assertFalse(m.observe(STA,ap,PEER,"invalid-ap"))
            self.assertFalse(m.timeline[-1]["facts"]["ap_response_valid"])
            m.observe(STA,AP,PEER,"valid")
            m.action("disconnect","stop")
            self.assertFalse(m.observe("address="+PEER+"\nwpa_state=DISCONNECTED",ap,PEER,"invalid-ap"))
            self.assertEqual(m.stage,Stage.DISCONNECTING)

    def test_associated_authorized_without_auth_does_not_confirm(self):
        m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER);m.action("connect","start")
        self.assertFalse(m.observe(STA,AP.replace("[AUTH]",""),PEER,"missing-auth"))
        self.assertEqual(m.stage,Stage.CONNECTING)

    def test_other_bssid_or_station_status_cannot_complete_connection(self):
        for changed in (STA.replace(BSSID,"02:00:00:00:00:bb"),
                        STA.replace(PEER,"02:00:00:00:00:02"),
                        STA.replace("bssid="+BSSID+"\n",""),
                        STA.replace("address="+PEER+"\n","")):
            m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER)
            m.action("connect","start")
            self.assertFalse(m.observe(changed,AP,PEER,"wrong-context"))
            self.assertEqual(m.stage,Stage.CONNECTING)
            self.assertTrue(m.observe(STA,AP,PEER,"valid"))

    def test_wrong_station_disconnected_does_not_complete_target_disconnect(self):
        m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER)
        m.action("connect","start");m.observe(STA,AP,PEER,"connected")
        m.action("disconnect","stop")
        self.assertFalse(m.observe("address=02:00:00:00:00:02\nwpa_state=DISCONNECTED",
                                   "FAIL",PEER,"other-station"))
        self.assertEqual(m.stage,Stage.DISCONNECTING)

    def test_invalid_target_identities_rejected_before_actions(self):
        for ap,sta in ((BSSID,BSSID),("ff:ff:ff:ff:ff:ff",PEER),(BSSID,None)):
            with self.assertRaises(ValueError):
                Lifecycle("wpa2","WPA2-PSK",bssid=ap,station=sta)

    def test_wrong_or_missing_cipher_never_confirms_baseline(self):
        for old,new in (("pairwise_cipher=CCMP","pairwise_cipher=TKIP"),
                        ("group_cipher=CCMP","group_cipher=TKIP"),
                        ("pairwise_cipher=CCMP","pairwise_cipher=GCMP"),
                        ("pairwise_cipher=CCMP\n",""),
                        ("group_cipher=CCMP\n","")):
            m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER)
            m.action("connect","start")
            self.assertFalse(m.observe(STA.replace(old,new),AP,PEER,"wrong-suite"))
            self.assertEqual(m.stage,Stage.CONNECTING)
            self.assertFalse(m.timeline[-1]["facts"]["cipher_profile_matches"])
            self.assertTrue(m.observe(STA,AP,PEER,"valid"))

    def test_reconnect_rechecks_cipher_instead_of_inheriting_previous_profile(self):
        m=Lifecycle("wpa2","WPA2-PSK",bssid=BSSID,station=PEER)
        m.action("connect","start");m.observe(STA,AP,PEER,"connected")
        m.action("disconnect","stop")
        m.observe("address="+PEER+"\nwpa_state=DISCONNECTED","FAIL",PEER,"removed")
        m.action("reconnect","restart")
        self.assertFalse(m.observe(STA.replace("pairwise_cipher=CCMP","pairwise_cipher=TKIP"),
                                   AP,PEER,"changed-suite"))
        self.assertEqual(m.stage,Stage.RECONNECTING)
        self.assertFalse(m.report()["passed"])
