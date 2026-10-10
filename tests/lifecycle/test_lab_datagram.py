import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest
from unittest.mock import patch
import tests.network.test_ccmp as fixture
from wifiseclab.lifecycle.lab_datagram import LabCcmpUplink, lab_request
from wifiseclab.lifecycle.udp_evidence import parse_udp


@unittest.skipIf(fixture.AESCCM is None,'Requires optional crypto')
class LabDatagramTests(unittest.TestCase):
    setUp=fixture.CcmpTests.setUp
    decrypt=fixture.CcmpTests.decrypt

    def test_normal_datagram_has_exact_addresses_checksums_and_payload(self):
        parsed=parse_udp(lab_request(bytes(range(16))))
        self.assertEqual(parsed['source'],['192.0.2.2',51000])
        self.assertEqual(parsed['destination'],['192.0.2.1',49321])
        self.assertEqual(parsed['payload'],b'WiFiSecLab-request:'+bytes(range(16)))
        self.assertTrue(parsed['udp_checksum_verified'])

    def test_allocator_never_reuses_pn_for_repeated_payload(self):
        sender=LabCcmpUplink(self.tk,self.ap,self.sta)
        first=sender.build_request(bytes(16));second=sender.build_request(bytes(16))
        self.assertEqual(self.decrypt(first)['pn'],1)
        self.assertEqual(self.decrypt(second)['pn'],2)
        self.assertEqual(self.decrypt(first)['plaintext'],self.decrypt(second)['plaintext'])
        self.assertNotEqual(first,second)

    def test_failed_encryption_burns_pn(self):
        sender=LabCcmpUplink(self.tk,self.ap,self.sta)
        with patch('cryptography.hazmat.primitives.ciphers.aead.AESCCM',side_effect=ValueError('test encryption failure')):
            with self.assertRaises(ValueError):sender.build_request(bytes(16))
        self.assertEqual(self.decrypt(sender.build_request(bytes(16)))['pn'],2)

    def test_exhaustion_and_invalid_input_do_not_wrap(self):
        sender=LabCcmpUplink(self.tk,self.ap,self.sta)
        with self.assertRaises(ValueError):sender.build_request(bytes(15))
        self.assertEqual(self.decrypt(sender.build_request(bytes(16)))['pn'],1)
        sender._next_pn=1<<48
        with self.assertRaises(ValueError):sender.build_request(bytes(16))
        with self.assertRaises(ValueError):LabCcmpUplink(self.tk,self.ap,self.ap)
