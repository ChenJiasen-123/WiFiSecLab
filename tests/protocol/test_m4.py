import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import importlib.util
import unittest
from unittest.mock import patch
import tests.protocol.test_eapol as golden
from tests.protocol.test_eapol import AP, STA, PMK, FRAMES, counter
from tests.protocol.test_wpa2 import association
from tests.protocol.test_advertisement import beacon
from tests.protocol.test_keydata import RSNE
from wifiseclab.protocol.wpa2 import build_m4


def advertisement():
    name = b'WiFiSecLab-hwsim'
    return beacon(bytes([0, len(name)]) + name + RSNE)


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'optional crypto extra unavailable')
class M4Tests(unittest.TestCase):
    setUp = golden.EapolTests.setUp
    analyze = golden.EapolTests.analyze

    def construct(self, **changes):
        args = dict(m1=FRAMES[0], m2=FRAMES[1], m3=FRAMES[2],
                    association=association(), advertisement=advertisement(), pmk=PMK,
                    eapol_version=FRAMES[3][32])
        return build_m4(**{**args, **changes})

    def test_independent_captured_m4_byte_exact_and_full_offline_path(self):
        reply = self.construct()
        self.assertEqual(reply[32:], FRAMES[3][32:])
        result = self.analyze([advertisement(), association(), *FRAMES[:3], reply], pmk=PMK, unwrap=True)
        self.assertTrue(result['rsne_bound_mic_verified_four_message_path_observed'])
        self.assertFalse(result['ap_authorization_confirmed'])

    def test_wrong_peer_nonce_counter_pmk_or_m2_fails(self):
        stranger = bytearray(FRAMES[2]); stranger[10] ^= 2
        nonce = bytearray(FRAMES[2]); nonce[49] ^= 1
        altered_m2 = bytearray(FRAMES[1]); altered_m2[-1] ^= 1
        first_counter = int.from_bytes(FRAMES[0][41:49], 'big')
        for changes in ({'m3': bytes(stranger)}, {'m3': bytes(nonce)},
                        {'m3': counter(FRAMES[2], first_counter)}, {'pmk': bytes(32)},
                        {'m2': bytes(altered_m2)}, {'sequence': 4096}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(ValueError):
                self.construct(**changes)

    def test_wrong_advertisement_ssid_or_rsne_fails(self):
        different_name = advertisement().replace(b'WiFiSecLab-hwsim', b'WrongName-hwsim!')
        different_rsn = bytearray(advertisement()); different_rsn[-2] ^= 1
        for adv in (different_name, bytes(different_rsn), b''):
            with self.assertRaises(ValueError):
                self.construct(advertisement=adv)

    def test_mic_failure_never_reaches_unwrap(self):
        changed = bytearray(FRAMES[2]); changed[113] ^= 1
        with patch('wifiseclab.protocol.wpa2.unwrap_key_data') as unwrap:
            with self.assertRaises(ValueError):
                self.construct(m3=bytes(changed))
            unwrap.assert_not_called()

    def test_formal_offline_cli_and_no_overwrite(self):
        import contextlib
        import io
        import json
        from pathlib import Path
        from wifiseclab.protocol.wpa2_cli import main
        root = Path(self.tmp.name)
        for name, value in (('m1', FRAMES[0]), ('m2', FRAMES[1]), ('m3', FRAMES[2]),
                            ('association', association()), ('advertisement', advertisement()), ('pmk', PMK)):
            (root / name).write_bytes(value)
        args = ['m4', '--pmk-file', str(root / 'pmk'), '--output', str(root / 'reply'),
                '--eapol-version', str(FRAMES[3][32])]
        for name in ('m1', 'm2', 'm3', 'association', 'advertisement'):
            args.extend(['--' + name, str(root / name)])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args), 0)
        result = json.loads(output.getvalue())
        self.assertFalse(result['transmitted'])
        self.assertNotIn(PMK.hex(), output.getvalue())
        self.assertEqual((root / 'reply').read_bytes()[32:], FRAMES[3][32:])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(args)
        self.assertEqual((root / 'reply').read_bytes()[32:], FRAMES[3][32:])
