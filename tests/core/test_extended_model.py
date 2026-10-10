import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
"""安全边界回归测试：检查顺序、重放及清理，不镜像每一行实现。"""
from tests.core.test_model import APModel, Event, Mode, e, load, codes
import unittest


class ExtendedTests(unittest.TestCase):
    def test_detailed_example(self):
        import json
        from pathlib import Path
        path = Path(__file__).resolve().parents[2] / "examples/wpa3_detailed.json"
        m = APModel(Mode.WPA3)
        for raw in json.loads(path.read_text(encoding="utf-8-sig")):
            m.apply(Event.parse(raw))
        self.assertFalse(m.findings)
        self.assertFalse(m.report()["abstractions_used"])

    def fresh(self, mode="wpa2", akm="psk"):
        m = APModel(Mode(mode))
        m.apply(e("session_start"))
        m.apply(e("auth_accepted", {"akm": akm}))
        m.apply(e("assoc_accepted", {"pmf": akm == "sae"}))
        return m

    def message(self, m, n, counter, exchange="h1"):
        m.apply(e("handshake_message", {"exchange_id": exchange, "message": n, "replay_counter": counter}))

    def test_detailed_handshake_and_retry(self):
        for mode, akm in (("wpa2", "psk"), ("wpa3", "sae"), ("transition", "sae")):
            m = self.fresh(mode, akm)
            m.apply(e("handshake_started", {"exchange_id": "h1"}))
            for n, c in ((1, 5), (1, 5), (2, 5), (3, 6), (4, 6)):
                self.message(m, n, c)
            m.apply(e("key_installed", {"slot": "ptk", "key_id": "k1"}))
            m.apply(e("handshake_completed"))
            m.apply(e("port_authorized"))
            self.assertFalse(m.findings)

    def test_out_of_order_and_early_complete(self):
        m = self.fresh()
        m.apply(e("handshake_started", {"exchange_id": "h1"}))
        self.message(m, 3, 6)
        m.apply(e("handshake_completed"))
        self.assertTrue({"HANDSHAKE_MESSAGE_ORDER", "INCOMPLETE_FOUR_WAY"} <= codes(m))

    def test_wrong_exchange_and_counter_do_not_advance(self):
        m = self.fresh()
        m.apply(e("handshake_started", {"exchange_id": "h1"}))
        self.message(m, 1, 10)
        self.message(m, 2, 11)
        self.message(m, 2, 10, "old")
        self.assertEqual(m.peers["sta1"].message, 1)
        self.assertTrue({"HANDSHAKE_REPLAY_COUNTER", "HANDSHAKE_CONTEXT"} <= codes(m))

    def test_sae_matching_exchange(self):
        m = APModel(Mode.WPA3)
        m.apply(e("session_start"))
        m.apply(e("sae_commit_accepted", {"exchange_id": "a1"}))
        m.apply(e("sae_confirm_accepted", {"exchange_id": "old"}))
        self.assertEqual(m.peers["sta1"].auth, "none")
        m.apply(e("sae_confirm_accepted", {"exchange_id": "a1"}))
        self.assertEqual(m.peers["sta1"].auth, "accepted")

    def test_sae_acceptance_keeps_four_way_context(self):
        m = APModel(Mode.WPA3)
        m.apply(e("session_start"))
        m.apply(e("sae_commit_accepted", {"exchange_id": "a1"}))
        # An independently reported four-way context cannot substitute for SAE.
        m.apply(e("handshake_started", {"exchange_id": "h1"}))
        m.apply(e("sae_confirm_accepted", {"exchange_id": "h1"}))
        self.assertEqual(m.peers["sta1"].auth, "none")
        m.apply(e("sae_confirm_accepted", {"exchange_id": "a1"}))
        p = m.peers["sta1"]
        self.assertEqual((p.sae, p.auth, p.exchange), ("accepted", "accepted", "h1"))
        self.assertIsNone(p.sae_exchange)

    def test_external_sae_confirm_cannot_complete_authentication(self):
        m = APModel(Mode.WPA3)
        m.apply(e("session_start"))
        m.apply(e("sae_commit_accepted", {"exchange_id": "a1"}))
        m.apply(e("sae_confirm_accepted", {"exchange_id": "a1"}, source="pcap"))
        self.assertEqual(m.peers["sta1"].auth, "none")
        self.assertEqual(m.peers["sta1"].sae_exchange, "a1")
        m.apply(e("auth_failed"))
        self.assertIsNone(m.peers["sta1"].sae_exchange)

    def test_timer_residue_and_expiry(self):
        m = self.fresh()
        m.apply(e("timer_started", {"timer_id": "retry"}))
        m.apply(e("disassociated"))
        m.apply(e("cleanup_checkpoint"))
        self.assertIn("RESIDUAL_CONTEXT", codes(m))
        m.apply(e("timer_cancelled", {"timer_id": "retry"}))
        m.apply(e("cleanup_checkpoint"))
        self.assertFalse(m.peers["sta1"].cleanup_required)

    def test_management_pmf(self):
        m = self.fresh("wpa3", "sae")
        m.apply(e("management_accepted", {"subtype": "deauth", "protected": False}))
        self.assertIn("UNPROTECTED_ROBUST_MGMT_ACCEPTED", codes(m))
        self.assertTrue(m.peers["sta1"].associated)

    def test_replay_ledger_not_lowered(self):
        m = load("wpa2_normal", "wpa2")
        for pn in (10, 5, 6):
            m.apply(e("data_accepted", {"key_id": "ptk-s1", "nonce_domain": "CCMP:STA:TID0", "pn": pn}))
        self.assertEqual(sum(f.code == "RX_REPLAY_ACCEPTED" for f in m.findings), 2)

    def test_session_id_cannot_be_recycled(self):
        m = APModel(Mode.WPA2)
        m.apply(e("session_start"))
        m.apply(e("session_start", session="s2"))
        m.apply(e("session_start"))
        self.assertIn("SESSION_ID_REUSE", codes(m))

    def test_malformed_input_atomic(self):
        m = self.fresh()
        before = m.peers["sta1"].snapshot()
        with self.assertRaises(ValueError):
            m.apply(e("handshake_message", {"exchange_id": "h1", "message": 1, "replay_counter": True}))
        self.assertEqual(m.peers["sta1"].snapshot(), before)

    def test_key_changes_count_in_coverage(self):
        m = self.fresh()
        m.apply(e("key_installed", {"slot": "ptk", "key_id": "k1"}))
        self.assertNotEqual(m.history[-1]["before"], m.history[-1]["after"])

    def test_associated_akm_switch_cannot_mutate(self):
        m = self.fresh("transition")
        m.apply(e("auth_accepted", {"akm": "sae"}))
        self.assertEqual(m.peers["sta1"].akm, "psk")

    def test_rekey_retains_old_key_until_explicit_change(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("rekey_started", {"exchange_id": "h2"}))
        self.assertEqual(m.peers["sta1"].keys["ptk"], "ptk-s1")
        self.assertTrue(m.peers["sta1"].authorized)
        for n, c in ((1, 1), (2, 1), (3, 2), (4, 2)):
            self.message(m, n, c, "h2")
        m.apply(e("key_installed", {"slot": "ptk", "key_id": "ptk-new"}))
        m.apply(e("handshake_completed"))
        self.assertFalse(m.findings)

    def test_timeout_does_not_hide_keys(self):
        m = load("wpa2_normal", "wpa2")
        m.apply(e("rekey_started"))
        m.apply(e("handshake_timeout"))
        m.apply(e("disassociated"))
        m.apply(e("cleanup_checkpoint"))
        self.assertIn("RESIDUAL_CONTEXT", codes(m))

    def test_external_acceptance_is_only_observation(self):
        m = self.fresh()
        m.apply(e("data_accepted", {"key_id": "unknown", "nonce_domain": "domain", "pn": 1}, source="pcap"))
        self.assertFalse(m.findings)
        self.assertFalse(m.rx_counters)
