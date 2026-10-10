import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import json
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from wifiseclab.core.model import APModel, Event, Mode

def e(kind, data=None, session="s1", source="synthetic", peer="sta1"):
    return Event(kind, peer, session, source, "test:" + kind, data or {})

def load(name, mode):
    model = APModel(Mode(mode))
    for raw in json.loads((ROOT / "examples" / (name + ".json")).read_text()):
        model.apply(Event.parse(raw))
    return model

def codes(model):
    return {f.code for f in model.findings}

class ModelTests(unittest.TestCase):
    def test_normal_profiles(self):
        for mode in ("wpa2", "wpa3", "transition"):
            with self.subTest(mode=mode):
                self.assertFalse(load(mode + "_normal", mode).findings)

    def test_reconnect_clean(self):
        self.assertFalse(load("reconnect_normal", "wpa2").findings)

    def test_reinstall_and_nonce_detected(self):
        self.assertEqual(codes(load("key_reinstall", "wpa2")),
                         {"KEY_REINSTALL_RESET", "NONCE_REUSE"})

    def test_cleanup_detected(self):
        self.assertIn("RESIDUAL_CONTEXT", codes(load("cleanup_residue", "wpa3")))

    def test_disconnection_does_not_assume_cleanup(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("disassociated"))
        self.assertIn("ptk", m.peers["sta1"].keys)
        self.assertTrue(m.peers["sta1"].authorized)

    def test_pcap_not_internal_truth(self):
        m = APModel(Mode.WPA2)
        m.apply(e("port_authorized", source="pcap"))
        self.assertFalse(m.peers)
        self.assertEqual(len(m.observations), 1)
        self.assertFalse(m.findings)

    def test_stale_session_does_not_mutate(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("port_revoked", session="old"))
        self.assertIn("STALE_SESSION_EVENT", codes(m))
        self.assertTrue(m.peers["sta1"].authorized)

    def test_unclean_replacement_blocked(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("session_start", session="s2"))
        self.assertIn("UNCLEAN_SESSION_REPLACEMENT", codes(m))
        self.assertEqual(m.peers["sta1"].session, "s1")

    def test_wpa3_rejects_psk(self):
        m = APModel(Mode.WPA3)
        m.apply(e("session_start"))
        m.apply(e("auth_accepted", {"akm": "psk"}))
        self.assertIn("AKM_POLICY", codes(m))

    def test_transition_accepts_psk(self):
        self.assertFalse(load("wpa2_normal", "transition").findings)

    def test_sae_requires_pmf(self):
        m = APModel(Mode.WPA3)
        m.apply(e("session_start"))
        m.apply(e("auth_accepted", {"akm": "sae"}))
        m.apply(e("assoc_accepted", {"pmf": False}))
        self.assertIn("SAE_WITHOUT_PMF", codes(m))

    def test_early_authorization(self):
        m = APModel(Mode.WPA2)
        m.apply(e("session_start"))
        m.apply(e("port_authorized"))
        self.assertIn("EARLY_AUTHORIZATION", codes(m))

    def test_link_retry_not_nonce_reuse(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("link_retry"))
        self.assertFalse(m.findings)

    def test_reinstall_preserving_counters(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("key_installed", {"key_id": "ptk-s1", "slot": "ptk", "counters_reset": False}))
        self.assertFalse(m.findings)

    def test_nonce_domain_separation(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("encrypt_new", {"key_id": "ptk-s1", "nonce_domain": "CCMP:AP:TID1", "nonce": 1}))
        self.assertFalse(m.findings)

    def test_nonce_ledger_survives_sessions(self):
        m = load("reconnect_normal", "wpa2")
        m.apply(e("key_installed", {"key_id": "ptk-s1", "slot": "ptk"}, session="s2"))
        m.apply(e("encrypt_new", {"key_id": "ptk-s1", "nonce_domain": "CCMP:AP:TID0", "nonce": 1}, session="s2"))
        self.assertIn("NONCE_REUSE", codes(m))

    def test_peers_isolated(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("session_start", peer="sta2"))
        self.assertFalse(m.peers["sta2"].authorized)
        self.assertTrue(m.peers["sta1"].authorized)

    def test_reject_malformed_event(self):
        with self.assertRaises(ValueError):
            Event.parse(dict(kind="x", peer="", session="s", source="synthetic", evidence="e"))

    def test_unknown_internal_event(self):
        m = APModel(Mode.WPA2)
        m.apply(e("session_start"))
        with self.assertRaises(ValueError):
            m.apply(e("unexpected"))

if __name__ == "__main__":
    unittest.main()
