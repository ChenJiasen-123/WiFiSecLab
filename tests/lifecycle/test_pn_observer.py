import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest
import tests.network.test_ccmp as ccmp_tests
from wifiseclab.lifecycle.pn_observer import PnObserver


@unittest.skipIf(ccmp_tests.AESCCM is None, 'Requires optional crypto')
class PnObserverTests(unittest.TestCase):
    setUp = ccmp_tests.CcmpTests.setUp
    decrypt = ccmp_tests.CcmpTests.decrypt

    def make(self, pn, payload=b'lab-only', priority=0):
        header = bytearray(self.frame[:24])
        header[0] = 136
        pn_le = pn.to_bytes(6, 'little')
        ccmp = pn_le[:2] + bytes([0,32]) + pn_le[2:]
        aad = bytes([136,header[1]&199]) + bytes(header[4:22]) + bytes(2) + bytes([priority,0])
        nonce = bytes([priority]) + bytes(header[10:16]) + pn_le[::-1]
        encrypted = ccmp_tests.AESCCM(self.tk, tag_length=8).encrypt(nonce,payload,aad)
        return bytes(header) + bytes([priority,0]) + ccmp + encrypted

    def test_masked_retry_is_duplicate_not_nonce_reuse(self):
        observer = PnObserver()
        observer.observe(1,self.frame,self.decrypt(self.frame))
        changed = bytearray(self.frame);changed[1] ^= 8;changed[22] ^= 240
        observer.observe(2,bytes(changed),self.decrypt(bytes(changed)))
        self.assertEqual(observer.events[0]['observation'],'duplicate_authenticated_ciphertext')
        self.assertFalse(observer.nonce_reuse)

    def test_same_nonce_distinct_verified_ciphertext_requires_review(self):
        observer = PnObserver()
        for i,payload in enumerate((b'first',b'second')):
            frame=self.make(10,payload)
            observer.observe(i,frame,self.decrypt(frame))
        self.assertTrue(observer.nonce_reuse)
        self.assertFalse(observer.report()['key_reinstallation_confirmed'])

    def test_priority_separation_and_capture_reorder(self):
        observer=PnObserver()
        for i,(pn,priority) in enumerate(((10,0),(9,0),(9,1))):
            frame=self.make(pn,priority=priority)
            observer.observe(i,frame,self.decrypt(frame))
        self.assertEqual(len(observer.events),1)
        self.assertEqual(observer.events[0]['observation'],'non_increasing_pn_in_capture_order')
        self.assertFalse(observer.nonce_reuse)
        self.assertFalse(observer.report()['receiver_replay_protection_confirmed'])

    def test_unverified_input_and_budget_do_not_silently_succeed(self):
        observer=PnObserver(budget=1)
        with self.assertRaises(ValueError):
            observer.observe(1,self.frame,{'mic_valid':False})
        self.assertEqual(observer.count,0)
        observer.observe(1,self.frame,self.decrypt(self.frame))
        observer.observe(2,self.frame,self.decrypt(self.frame))
        self.assertTrue(observer.report()['observation_incomplete'])
