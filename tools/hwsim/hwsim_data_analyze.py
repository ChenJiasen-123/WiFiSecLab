#!/usr/bin/env python3
"""Offline PSK hwsim bundle analysis; reads a known 32-byte lab PMK."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from wifiseclab.protocol.eapol import analyze_handshake
from wifiseclab.lifecycle.data_evidence import correlate_data
from wifiseclab.lifecycle.encrypted_evidence import verify_capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--pmk-file', type=Path, required=True)
    args = parser.parse_args()
    pmk = args.pmk_file.read_bytes()
    if len(pmk) != 32:
        parser.error('PMK file must contain exactly 32 raw bytes')
    case = args.case
    snapshot_meta = json.loads((case / 'ap-snapshot-metadata.json').read_bytes())
    report = analyze_handshake(case / 'air.pcap', snapshot_meta['bssid'], snapshot_meta['station'], pmk=pmk, unwrap=True)
    digest = hashlib.sha256((case / 'air.pcap').read_bytes()).hexdigest()
    data = correlate_data(report, (case / 'ap-stations.txt').read_bytes(), snapshot_meta, digest,
                          (case / 'udp-client.json').read_bytes(), (case / 'udp-server.json').read_bytes(),
                          json.loads((case / 'data-metadata.json').read_bytes()))
    encrypted = verify_capture(case / 'air.pcap', report, pmk,
                               json.loads((case / 'udp-client.json').read_bytes()),
                               json.loads((case / 'udp-server.json').read_bytes()), data)
    data['encrypted_capture'] = encrypted
    data['encrypted_application_round_trip_observed'] = (
        data['correlated'] and encrypted['encrypted_round_trip_observed'])
    print(json.dumps(data, indent=2))
    return 0 if data['encrypted_application_round_trip_observed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
