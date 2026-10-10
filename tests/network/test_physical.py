import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import json
from pathlib import Path
import struct
import zlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wifiseclab.network.physical import PhysicalRadioAdapter, captured_frames
from wifiseclab.network.radio_roles import Radio, RadioRoles


class PhysicalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / "run"
        a = Radio("wlan1", "phy1", "0cf3:9271", "ath9k_htc", True, frozenset({2412}))
        b = Radio("wlan0", "phy0", "0e8d:7612", "mt76x2u", True, frozenset({2412}))
        self.roles = RadioRoles.bind([a, b])
        self.frame = bytes.fromhex("80000000") + b"\xff" * 20 + b"test"

    def pcap(self, frame, with_fcs=False):
        self.output.mkdir(exist_ok=True)
        if with_fcs:
            data = bytes.fromhex('000009000200000010') + frame + struct.pack('<I', zlib.crc32(frame))
        else:
            data = b"\x00\x00\x08\x00\x00\x00\x00\x00" + frame
        path = self.output / "air.pcap"
        path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 4096, 127)
                         + struct.pack("<IIII", 0, 0, len(data), len(data)) + data)
        return path

    @patch("wifiseclab.network.physical.socket.AF_PACKET", 17, create=True)
    def test_send_uses_injector_and_requires_capture(self):
        factory = MagicMock()
        tx = factory.return_value.__enter__.return_value
        tx.send.return_value = len(self.frame) + 8
        adapter = PhysicalRadioAdapter(self.roles, self.output, socket_factory=factory)
        with self.assertRaises(RuntimeError):
            adapter.send(self.frame)
        adapter.active = True
        adapter.capture = Mock()
        adapter.capture.poll.return_value = None
        action = adapter.send(self.frame)
        tx.bind.assert_called_once_with(("wslabtx", 0))
        tx.settimeout.assert_called_once_with(.5)
        self.assertIsNone(action["over_air_observed"])
        self.assertIsNone(action["ap_accepted"])
        for frame in (b"short", b"\x04" + bytes(23)):
            with self.assertRaises(ValueError):
                adapter.send(frame)

    def test_capture_matches_without_inventing_acceptance(self):
        self.pcap(self.frame, with_fcs=True)
        adapter = PhysicalRadioAdapter(self.roles, self.output)
        adapter.actions = [{"frame_hex": self.frame.hex(), "ap_accepted": None}]
        report = adapter.report()
        self.assertTrue(report["actions"][0]["over_air_observed"])
        self.assertIsNone(report["actions"][0]["ap_accepted"])

    def test_missing_or_truncated_capture_is_unknown(self):
        self.output.mkdir()
        adapter = PhysicalRadioAdapter(self.roles, self.output)
        adapter.actions = [{"frame_hex": self.frame.hex()}]
        self.assertIsNone(adapter.report()["actions"][0]["over_air_observed"])
        path = self.pcap(self.frame)
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            list(captured_frames(path))

    def test_partial_setup_cleans_only_owned_interfaces(self):
        inventory = "phy#1\n\tInterface wlan1\nphy#0\n\tInterface wlan0\n"
        def run(args, **kwargs):
            if args == ["iw", "dev"]:
                return inventory
            if args[-1] == "link":
                return "Not connected."
            if args[:3] == ["ip", "link", "set"]:
                raise RuntimeError("setup failed")
            return ""
        mock = Mock(side_effect=run)
        adapter = PhysicalRadioAdapter(self.roles, self.output, run=mock)
        with self.assertRaisesRegex(RuntimeError, "setup failed"):
            adapter.start()
        self.assertEqual(adapter.created, [])
        self.assertIn(["iw", "dev", "wslabtx", "del"], [c.args[0] for c in mock.call_args_list])
        self.assertNotIn(["iw", "dev", "wlan1", "del"], [c.args[0] for c in mock.call_args_list])

    def test_existing_output_preserved(self):
        self.output.mkdir()
        adapter = PhysicalRadioAdapter(self.roles, self.output)
        with self.assertRaises(FileExistsError):
            adapter.start()
        self.assertFalse(adapter.output_created)
