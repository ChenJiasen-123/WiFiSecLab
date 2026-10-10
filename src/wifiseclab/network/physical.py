"""Linux dual-radio execution and independent capture; no AP-state inference."""
import hashlib
import json
import math
import re
from pathlib import Path
import socket
import struct
import subprocess
import time

from wifiseclab.network.radio_roles import RadioRoles, discover
from wifiseclab.network.capture import decode_radiotap


def captured_records(path, allow_incomplete=False, stats=None):
    """Yield (1-based record index, timestamp, 802.11 bytes).

    Live readers may ignore an incomplete final record; final analysis is strict.
    """
    with open(path, "rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("Incomplete pcap header")
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(header[:4])
        if endian is None or struct.unpack(endian + "I", header[20:24])[0] != 127:
            raise ValueError("Expected classic pcap with radiotap link type 127")
        index = 0
        precision = 1_000_000_000 if header[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1_000_000
        while True:
            record = stream.read(16)
            if not record:
                return
            if len(record) != 16:
                if allow_incomplete:
                    return
                raise ValueError("Incomplete pcap record")
            seconds, fraction, size, original_size = struct.unpack(endian + "IIII", record)
            index += 1
            if stats is not None:
                stats['pcap_records'] = index
            if size > 262144:
                raise ValueError("Oversized pcap record")
            if size != original_size:
                raise ValueError('Snapshot-truncated or inconsistent pcap packet length')
            if fraction >= precision:
                raise ValueError('Invalid pcap timestamp fraction')
            packet = stream.read(size)
            if len(packet) != size:
                if allow_incomplete:
                    return
                raise ValueError("Truncated pcap packet")
            frame = decode_radiotap(packet, stats)
            if frame is not None:
                yield index, seconds + fraction / precision, frame


def captured_frames(path):
    for _, _, frame in captured_records(path):
        yield frame


def management_frame_matches(expected, observed):
    """Allow only observed driver rewrites: duration, retry and sequence number.

    Addresses, body, subtype, other flags and fragment number must still match.
    This is semantic observation, never proof of AP acceptance.
    """
    if len(expected) < 24 or len(observed) != len(expected) or expected[0] & 15:
        return False
    def normalized(frame):
        result = bytearray(frame)
        result[1] &= ~8
        result[2:4] = b"\x00\x00"
        result[22] &= 15
        result[23] = 0
        return bytes(result)
    return normalized(expected) == normalized(observed)


class PhysicalRadioAdapter:
    """Own only temporary monitor interfaces, never reset the AP itself."""
    interfaces = {"injector": "wslabtx", "listener": "wslabrx"}

    def __init__(self, roles, output, run=subprocess.check_output,
                 popen=subprocess.Popen, socket_factory=socket.socket, send_timeout=.5):
        if type(send_timeout) not in (int, float) or not math.isfinite(send_timeout) or not 0 < send_timeout <= 2:
            raise ValueError('send_timeout must be finite and in (0, 2] seconds')
        self.send_timeout = send_timeout
        self.roles = roles
        self.output = Path(output)
        self.run, self.popen, self.socket_factory = run, popen, socket_factory
        self.created = []
        self.capture = None
        self.capture_log = None
        self.active = False
        self.actions = []
        self.cleanup_errors = []
        self.output_created = False
        self.capture_exit_code = None

    def command(self, *args):
        return self.run(list(args), text=True, stderr=subprocess.STDOUT)

    def start(self):
        if self.active or self.created:
            raise RuntimeError("Adapter already started")
        self.output.mkdir(parents=True, exist_ok=False)
        self.output_created = True
        # Refuse connected radios: their shared PHY channel must not be disturbed.
        inventory = self.command("iw", "dev")
        for name in self.interfaces.values():
            if f"Interface {name}\n" in inventory:
                raise RuntimeError(f"Existing interface: {name}")
        for radio in (self.roles.injector, self.roles.listener):
            if "Not connected." not in self.command("iw", "dev", radio.interface, "link"):
                raise RuntimeError(f"Radio is connected or state unknown: {radio.interface}")
            # Reject another virtual interface on the same PHY.
            block = next((b for b in re.split(r"(?m)^phy#", inventory)
                          if b.startswith(radio.phy.removeprefix("phy") + "\n")), "")
            names = re.findall(r"(?m)^\s*Interface (\S+)", block)
            if names != [radio.interface]:
                raise RuntimeError(f"Unexpected interfaces on {radio.phy}: {names}")
        try:
            for role in ("injector", "listener"):
                radio = getattr(self.roles, role)
                name = self.interfaces[role]
                self.command("iw", "phy", radio.phy, "interface", "add", name, "type", "monitor")
                self.created.append(name)
                self.command("ip", "link", "set", name, "up")
                self.command("iw", "dev", name, "set", "channel", str(self.roles.channel))
            self.capture_log = open(self.output / "capture.log", "w")
            self.capture = self.popen(["tcpdump", "-i", self.interfaces["listener"],
                                       "-U", "-n", "-s", "4096", "-w", str(self.output / "air.pcap")],
                                      stdout=self.capture_log, stderr=self.capture_log)
            # Wait for tcpdump to create its pcap header, not an arbitrary startup sleep.
            deadline = time.monotonic() + 5
            while True:
                if self.capture.poll() is not None:
                    raise RuntimeError("Capture failed; see capture.log")
                path = self.output / "air.pcap"
                if path.exists() and path.stat().st_size >= 24:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Capture startup timed out")
                time.sleep(0.05)
            self.active = True
        except BaseException:
            self.close()
            raise
        return self

    def send(self, frame):
        """Submit one raw 802.11 management/data frame, without FCS or radiotap."""
        if not self.active or self.capture is None or self.capture.poll() is not None:
            raise RuntimeError("Independent capture must be running before transmission")
        if not isinstance(frame, bytes) or not 24 <= len(frame) <= 2304:
            raise ValueError("Expected 24..2304 bytes of raw 802.11 frame")
        if frame[0] & 3 or ((frame[0] >> 2) & 3) not in (0, 2):
            raise ValueError("Expected 802.11 management or data frame")
        packet = b"\x00\x00\x08\x00\x00\x00\x00\x00" + frame
        with self.socket_factory(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as tx:
            tx.settimeout(self.send_timeout)
            tx.bind((self.interfaces["injector"], 0))
            submitted_before_ns = time.time_ns()
            size = tx.send(packet)
        if size != len(packet):
            raise RuntimeError("Incomplete frame submission")
        action = {"kind": "frame_submitted", "time_ns": time.time_ns(),
                  "submitted_before_ns": submitted_before_ns,
                  "interface": self.interfaces["injector"], "sha256": hashlib.sha256(frame).hexdigest(),
                  "frame_hex": frame.hex(), "bytes": len(frame),
                  "over_air_observed": None, "ap_accepted": None}
        self.actions.append(action)
        return action

    def close(self):
        self.active = False
        if self.capture is not None:
            try:
                if self.capture.poll() is None:
                    self.capture.terminate()
                    try:
                        self.capture.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.capture.kill()
                        self.capture.wait(timeout=5)
                self.capture_exit_code = self.capture.poll()
            except Exception as exc:
                self.cleanup_errors.append(str(exc))
            self.capture = None
        if self.capture_log is not None:
            self.capture_log.close()
            self.capture_log = None
        for name in list(reversed(self.created)):
            try:
                self.command("iw", "dev", name, "del")
                self.created.remove(name)
            except Exception as exc:
                self.cleanup_errors.append(f"{name}: {exc}")

    def report(self):
        if self.active or self.capture is not None:
            raise RuntimeError("Stop capture before evaluating evidence")
        counts = {action["frame_hex"]: 0 for action in self.actions}
        semantic_counts = dict.fromkeys(counts, 0)
        packets, error = 0, None
        quality = {}
        try:
            for _, _, frame in captured_records(self.output / "air.pcap", stats=quality):
                packets += 1
                # FCS handling happens once, using radiotap metadata and CRC.
                for raw in counts:
                    expected = bytes.fromhex(raw)
                    if frame == expected:
                        counts[raw] += 1
                        semantic_counts[raw] += 1
                    elif management_frame_matches(expected, frame):
                        semantic_counts[raw] += 1
        except (OSError, ValueError) as exc:
            error = str(exc)
        result = {"roles": self.roles.report(), "capture_packets": packets,
                  "capture_quality": quality,
                  "capture_exit_code": self.capture_exit_code,
                  "injection_observed_this_run": any(semantic_counts.values()),
                  "capture_error": error, "cleanup_errors": self.cleanup_errors,
                  "actions": [{**a, "matching_capture_packets": counts[a["frame_hex"]],
                               "semantic_matching_capture_packets": semantic_counts[a["frame_hex"]],
                               "over_air_observed": True if semantic_counts[a["frame_hex"]] else None}
                              for a in self.actions],
                  "limitations": "Independent frame observation is not causal proof or AP acceptance. Management matching tolerates duration/retry/sequence-number rewrites only; exact counts are reported separately. Repeated identical submissions cannot be uniquely attributed. AP internal state requires instrumentation."}
        (self.output / "physical-report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
