"""Construct baseline WPA2 responses offline from explicit raw frame inputs."""
import argparse
import hashlib
import json
from pathlib import Path
from .wpa2 import build_m2, build_m4


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=('m2', 'm4'))
    for name in ('m1', 'association', 'pmk-file', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('m2', 'm3', 'advertisement'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--sequence', type=int, default=0)
    parser.add_argument('--eapol-version', type=int, choices=(1, 2, 3), default=2)
    args = parser.parse_args(argv)
    try:
        extras = (args.m2, args.m3, args.advertisement)
        if args.kind == 'm4' and not all(extras):
            raise ValueError('M4 requires --m2, --m3 and --advertisement')
        if args.kind == 'm2' and any(extras):
            raise ValueError('M2 does not use --m2, --m3 or --advertisement')
        m1, assoc, pmk = args.m1.read_bytes(), args.association.read_bytes(), args.pmk_file.read_bytes()
        options = {'sequence': args.sequence, 'eapol_version': args.eapol_version}
        if args.kind == 'm2':
            frame = build_m2(m1, assoc, pmk, **options)
        else:
            frame = build_m4(m1, args.m2.read_bytes(), args.m3.read_bytes(), assoc,
                             args.advertisement.read_bytes(), pmk, **options)
        with args.output.open('xb') as stream:
            stream.write(frame)
        print(json.dumps({'kind': args.kind, 'frame_length': len(frame),
                          'frame_sha256': hashlib.sha256(frame).hexdigest(),
                          'format': 'raw-80211-without-radiotap-or-fcs',
                          'transmitted': False, 'ap_acceptance_confirmed': False}))
        return 0
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
