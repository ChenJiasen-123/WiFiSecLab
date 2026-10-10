import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import struct
import unittest
from tests.protocol.test_eapol import FRAMES, PMK
from tests.protocol.test_wpa2 import association
from tests.protocol.test_m4 import advertisement
from wifiseclab.protocol.association_gate import association_evidence, admitted_session


def response(status=0, aid=0xc001, ies=b'\x01\x02\x82\x84'):
    request = association()
    return (b'\x10\x00\x00\x00' + request[10:16] + request[4:10] + request[16:24] +
            struct.pack('<HHH', 0x431, status, aid) + ies)


class AssociationGateTests(unittest.TestCase):
    def evidence(self, records, **kwargs):
        return association_evidence(association(), records, now=1, **kwargs)

    def test_success_without_rsne_admits_and_preserves_capture_evidence(self):
        records = [(.1, association()), (.2, response())]
        result = self.evidence(records)
        self.assertTrue(result['eligible'])
        self.assertFalse(result['ap_internal_association_confirmed'])
        self.assertFalse(result['ap_identity_authenticated'])
        session = admitted_session(association(), advertisement(), PMK, records, now=1)
        self.assertEqual(session.report()['association_admission_evidence'], result)
        self.assertIsNotNone(session.receive(FRAMES[0], 1.1))

    def test_stale_missing_preceding_request_and_wrong_addresses_reject(self):
        wrong = bytearray(response()); wrong[4] ^= 4
        for records in ([(.1, response()), (.2, association())],
                        [(.1, response())], [(.1, association()), (.2, bytes(wrong))]):
            self.assertFalse(self.evidence(records)['eligible'])
        self.assertFalse(self.evidence([(.1, association()), (.2, response())], window=.5)['eligible'])

    def test_rejection_invalid_aid_and_conflicts_block_factory(self):
        for replies in ([response(status=17)], [response(aid=0)],
                        [response(aid=0xc7d8)], [response(), response(status=17)],
                        [response(), response(aid=0xc002)]):
            records = [(.1, association())] + [(.2 + n * .01, frame) for n, frame in enumerate(replies)]
            self.assertFalse(self.evidence(records)['eligible'])
            with self.assertRaises(ValueError):
                admitted_session(association(), advertisement(), PMK, records, now=1)

    def test_identical_success_retries_are_accepted(self):
        retry = bytearray(response()); retry[1] |= 8; retry[22:24] = b'\x20\x00'
        self.assertTrue(self.evidence([(.1, association()), (.2, response()),
                                       (.3, bytes(retry))])['eligible'])

    def test_boundary_and_malformed_responses_cannot_be_hidden_by_success(self):
        deauth = bytearray(response()[:24]); deauth[0] = 0xc0; deauth += b'\x03\x00'
        for bad in (bytes(deauth), response()[:27], response(ies=b'\x01\x08\x82'),
                    response(ies=b''), response(ies=b'\x01\x01\x82\x01\x01\x84')):
            self.assertFalse(self.evidence([(.1, association()), (.2, response()), (.3, bad)])['eligible'])

    def test_clock_domain_and_record_budget_must_be_valid(self):
        for records in ([(.2, association()), (.1, response())],
                        [(2, association())], [(float('nan'), association())],
                        [(0, association())] * 4097):
            with self.assertRaises(ValueError):
                self.evidence(records)
