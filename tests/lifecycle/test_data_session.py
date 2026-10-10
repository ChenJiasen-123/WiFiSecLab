import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import unittest
import tests.network.test_ccmp as fixture
from wifiseclab.lifecycle.data_session import DataSession
from wifiseclab.lifecycle.udp_evidence import parse_udp,checksum


@unittest.skipIf(fixture.AESCCM is None,'Requires optional crypto')
class DataSessionTests(unittest.TestCase):
    setUp=fixture.CcmpTests.setUp
    decrypt=fixture.CcmpTests.decrypt

    def bundle(self):
        response=bytes.fromhex(self.fixture['frames'][1]['frame_hex'])
        plaintext=bytearray(self.decrypt(response)['plaintext'])
        plaintext[30:32]=(51000).to_bytes(2,'big')
        plaintext[34:36]=bytes(2)
        pseudo=bytes(plaintext[20:28])+bytes([0,17])+(len(plaintext)-28).to_bytes(2,'big')
        plaintext[34:36]=(checksum(pseudo+plaintext[28:]) or 65535).to_bytes(2,'big')
        ccmp=response[24:32];pn=ccmp[:2]+ccmp[4:]
        aad=bytes([response[0]&143,response[1]&199])+response[4:22]+bytes(2)
        nonce=bytes(1)+self.ap+pn[::-1]
        response=response[:32]+fixture.AESCCM(self.tk,tag_length=8).encrypt(nonce,bytes(plaintext),aad)
        token=parse_udp(bytes(plaintext))['payload'][-16:]
        session=DataSession(self.tk,self.ap,self.sta,token,started_at=0)
        session.build_request(0)
        return session,response

    def test_real_response_completes_once(self):
        session,response=self.bundle()
        self.assertIsNotNone(session.receive(response,1))
        self.assertTrue(session.report()['encrypted_response_observed'])
        self.assertIsNone(session.receive(response,1.1))
        with self.assertRaises(ValueError):session.build_request(1.2)

    def test_disconnect_unicast_and_broadcast_prevent_old_response(self):
        for destination in (self.sta,bytes([255])*6):
            session,response=self.bundle()
            frame=bytes.fromhex('c0000000')+destination+self.ap+self.ap+bytes(2)+bytes([1,0])
            session.receive(frame,.5)
            self.assertEqual(session.reason,'observed_management_boundary')
            self.assertIsNone(session.receive(response,1))
            self.assertFalse(session.verified_response)

    def test_clear_rekey_and_protected_management_close_context(self):
        for frame in (bytes.fromhex('08020000')+self.sta+self.ap+self.ap+bytes(2)+bytes.fromhex('aaaa03000000888e02030000'),
                      bytes.fromhex('c0400000')+self.sta+self.ap+self.ap+bytes(10)):
            session,response=self.bundle()
            session.receive(frame,.5)
            self.assertEqual(session.phase,'closed')
            self.assertIsNone(session.receive(response,1))

    def test_other_peer_boundary_does_not_close_context(self):
        session,response=self.bundle()
        frame=bytes.fromhex('c0000000')+bytes.fromhex('020000000099')+self.ap+self.ap+bytes(4)
        session.receive(frame,.5)
        self.assertIsNotNone(session.receive(response,1))

    def test_bad_mic_deadline_and_clock_do_not_promote_success(self):
        session,response=self.bundle();changed=bytearray(response);changed[-1]^=1
        self.assertIsNone(session.receive(bytes(changed),.5))
        self.assertIsNone(session.receive(response,2))
        self.assertEqual(session.phase,'expired')
        session,response=self.bundle();session.receive(bytes(changed),.5)
        with self.assertRaises(ValueError):session.receive(response,.4)
        self.assertEqual(session.phase,'closed')
