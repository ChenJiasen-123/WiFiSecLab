import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "src"))
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from wifiseclab.network.network_guard import NetworkGuard


class NetworkGuardTests(unittest.TestCase):
    def run_command(self, args, **kwargs):
        if args[-1] == 'link':
            return 'Not connected.'
        if 'GENERAL.NM-MANAGED' in args:
            return 'yes' if args[-1] == 'wlan0' else 'no'
        return ''

    def test_restores_original_flags_and_management(self):
        run = Mock(side_effect=self.run_command)
        with NetworkGuard(['wlan0', 'wlan1'], run, flags=lambda dev: int(dev == 'wlan0'), nmcli=True):
            pass
        calls = [c.args[0] for c in run.call_args_list]
        self.assertIn(['ip', 'link', 'set', 'wlan0', 'up'], calls)
        self.assertIn(['ip', 'link', 'set', 'wlan1', 'down'], calls)
        self.assertEqual(calls[-1], ['nmcli', 'device', 'set', 'wlan0', 'managed', 'yes'])

    def test_partial_failure_still_restores(self):
        def command(args, **kwargs):
            if args == ['ip', 'link', 'set', 'wlan0', 'down']:
                raise RuntimeError('down failed')
            return self.run_command(args, **kwargs)
        run = Mock(side_effect=command)
        guard = NetworkGuard(['wlan0'], run, flags=lambda dev: 1, nmcli=True)
        with self.assertRaises(RuntimeError):
            guard.__enter__()
        self.assertEqual(run.call_args_list[-1].args[0], ['nmcli', 'device', 'set', 'wlan0', 'managed', 'yes'])

    def test_connected_second_radio_prevents_all_changes(self):
        def command(args, **kwargs):
            if args == ['iw', 'dev', 'wlan1', 'link']:
                return 'Connected to 00:11:22:33:44:55'
            return self.run_command(args, **kwargs)
        run = Mock(side_effect=command)
        with self.assertRaises(RuntimeError):
            with NetworkGuard(['wlan0', 'wlan1'], run, flags=lambda dev: 1, nmcli=True):
                pass
        self.assertFalse(any('set' in call.args[0] for call in run.call_args_list))

    def test_restore_failure_does_not_skip_other_restorations(self):
        run = Mock(side_effect=self.run_command)
        guard = NetworkGuard(['wlan0', 'wlan1'], run, flags=lambda dev: 1, nmcli=True)
        guard.__enter__()
        def command(args, **kwargs):
            if args == ['ip', 'link', 'set', 'wlan1', 'up']:
                raise RuntimeError('restore failed')
            return self.run_command(args, **kwargs)
        run.side_effect = command
        guard.restore()
        self.assertEqual(len(guard.cleanup_errors), 1)
        self.assertEqual(run.call_args_list[-1].args[0], ['nmcli', 'device', 'set', 'wlan0', 'managed', 'yes'])
