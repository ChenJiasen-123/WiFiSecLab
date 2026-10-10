#!/usr/bin/env python3
"""Offline response construction without installing the package."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from wifiseclab.protocol.wpa2_cli import main

if __name__ == '__main__':
    raise SystemExit(main())
