"""Pause NetworkManager scanning on selected idle radios and restore state."""
from pathlib import Path
import shutil
import subprocess


class NetworkGuard:
    def __init__(self, interfaces, run=subprocess.check_output, flags=None, nmcli=None):
        self.interfaces = list(interfaces)
        self.run = run
        self.flags = flags or (lambda dev: int((Path('/sys/class/net') / dev / 'flags').read_text(), 16))
        self.nmcli = shutil.which('nmcli') is not None if nmcli is None else nmcli
        self.saved = []
        self.cleanup_errors = []

    def command(self, *args):
        return self.run(list(args), text=True, stderr=subprocess.STDOUT)

    def __enter__(self):
        if self.saved:
            raise RuntimeError('Network guard already entered')
        states = []
        # Read all initial states before changing either radio.
        for dev in self.interfaces:
            if 'Not connected.' not in self.command('iw', 'dev', dev, 'link'):
                raise RuntimeError('Connected radio or unknown link state: ' + dev)
            managed = None
            if self.nmcli:
                managed = self.command('nmcli', '-g', 'GENERAL.NM-MANAGED', 'device', 'show', dev).strip()
                if managed not in ('yes', 'no'):
                    raise RuntimeError('Unknown NetworkManager state: ' + dev)
            states.append((dev, managed, bool(self.flags(dev) & 1)))
        try:
            for state in states:
                dev, managed, _ = state
                self.saved.append(state)
                if managed is not None:
                    self.command('nmcli', 'device', 'set', dev, 'managed', 'no')
                self.command('ip', 'link', 'set', dev, 'down')
        except BaseException:
            self.restore()
            raise
        return self

    def restore(self):
        for dev, managed, up in reversed(self.saved):
            # Attempt both restorations even when one fails; record every error.
            operations = [('ip', 'link', 'set', dev, 'up' if up else 'down')]
            if managed is not None:
                operations.append(('nmcli', 'device', 'set', dev, 'managed', managed))
            for args in operations:
                try:
                    self.command(*args)
                except Exception as exc:
                    self.cleanup_errors.append(f'{dev}: {exc}')
        self.saved.clear()

    def __exit__(self, *exc):
        self.restore()
