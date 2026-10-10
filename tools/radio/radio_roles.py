#!/usr/bin/env python3
"""Inspect physical radio roles on the Linux experiment host; never transmit."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wifiseclab.network.radio_roles import RadioRoles, discover


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", type=int, default=1)
    args = parser.parse_args()
    try:
        roles = RadioRoles.bind(discover(), args.channel)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(json.dumps(roles.report(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
