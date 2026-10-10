#!/usr/bin/env python3
"""Run a bounded dual-radio capture with optional raw-frame submission."""
import argparse
import json
from pathlib import Path
import signal
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from wifiseclab.network.physical import PhysicalRadioAdapter
from wifiseclab.network.radio_roles import RadioRoles, discover
from wifiseclab.network.network_guard import NetworkGuard


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory")
    parser.add_argument("--duration", type=float, default=3)
    parser.add_argument("--frame", type=Path, help="Binary 802.11 frame without radiotap/FCS; omitted means passive only")
    args = parser.parse_args()
    if not 0 < args.duration <= 60:
        parser.error("duration must be 0..60 seconds (exclusive of 0)")
    frame = args.frame.read_bytes() if args.frame else None
    adapter = PhysicalRadioAdapter(RadioRoles.bind(discover(), args.channel), args.output)
    guard = NetworkGuard([adapter.roles.injector.interface, adapter.roles.listener.interface])
    def interrupted(signum, stack):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with guard:
            with adapter:
                if frame is not None:
                    adapter.send(frame)
                time.sleep(args.duration)
    finally:
        if adapter.output_created:
            result = adapter.report()
            result['cleanup_errors'].extend(guard.cleanup_errors)
            (args.output / 'physical-report.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
            print(json.dumps(result, indent=2))
    if result["capture_error"] or result["cleanup_errors"] or result["capture_exit_code"] != 0:
        return 2
    if frame is not None and not result["injection_observed_this_run"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
