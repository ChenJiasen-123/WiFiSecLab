import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import sys
import unittest
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wifiseclab.network.radio_roles import Radio, RadioRoles


class RadioRoleTests(unittest.TestCase):
    def setUp(self):
        self.injector = Radio("wlan1", "phy1", "0cf3:9271", "ath9k_htc", True, frozenset({2412, 2437, 2462}))
        self.listener = Radio("wlan0", "phy0", "0e8d:7612", "mt76x2u", True, frozenset({2412, 2437, 2462, 5180}))

    def test_hardware_binding_survives_interface_renumbering(self):
        radios = [replace(self.injector, interface="wlan0", phy="phy0"),
                  replace(self.listener, interface="wlan1", phy="phy1")]
        roles = RadioRoles.bind(radios, 6)
        self.assertEqual(roles.interface_for("injector"), "wlan0")
        self.assertEqual(roles.interface_for("listener"), "wlan1")
        self.assertFalse(roles.report()["injection_verified"])

    def test_missing_or_ambiguous_hardware_rejected(self):
        for radios in ([self.listener], [self.injector, self.injector, self.listener]):
            with self.assertRaises(ValueError):
                RadioRoles.bind(radios)

    def test_invalid_arrangements_rejected(self):
        for listener in (replace(self.listener, phy="phy1"),
                         replace(self.listener, interface="wlan1"),
                         replace(self.listener, driver="wrong"),
                         replace(self.listener, monitor_supported=False),
                         replace(self.listener, frequencies=frozenset({5180}))):
            with self.assertRaises(ValueError):
                RadioRoles.bind([self.injector, listener])

    def test_unsupported_channel_and_unknown_role_rejected(self):
        for channel in (0, 12, 36, True):
            with self.assertRaises(ValueError):
                RadioRoles.bind([self.injector, self.listener], channel)
        with self.assertRaises(ValueError):
            RadioRoles.bind([self.injector, self.listener]).interface_for("capture")
