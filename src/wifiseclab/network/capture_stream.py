"""Incremental classic radiotap pcap consumption for a single append-only file."""
import os
import math
import struct
from wifiseclab.network.capture import decode_radiotap


class GrowingCapture:
    def __init__(self, path):
        self.stream = open(path, 'rb', buffering=0)
        self.offset, self.index, self.high_water = 0, 0, 0
        self.endian, self.precision, self.snaplen = None, None, None
        self.stats = {}
        self.failed = False

    def _take(self, count):
        size = os.fstat(self.stream.fileno()).st_size
        if size < self.high_water:
            raise ValueError('Capture file shrank; a new capture context is required')
        self.high_water = size
        self.stream.seek(self.offset)
        data = self.stream.read(count)
        return data if len(data) == count else None

    def next_record(self):
        """Return (1-based index, capture time, frame-or-None), or None if pending.

        A complete rejected-FCS record is consumed exactly once, with frame None.
        Partial records remain pending. Any parse error poisons this reader.
        """
        if self.failed:
            raise ValueError('Capture reader failed; do not resume this context')
        try:
            return self._next_record()
        except (ValueError, OSError):
            self.failed = True
            raise

    def _next_record(self):
        if self.endian is None:
            header = self._take(24)
            if header is None:
                return None
            magic = {b'\xd4\xc3\xb2\xa1': ('<', 1000000),
                     b'\xa1\xb2\xc3\xd4': ('>', 1000000),
                     b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
                     b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
            if header[:4] not in magic:
                raise ValueError('Expected classic pcap')
            endian, precision = magic[header[:4]]
            major, minor, _, _, snaplen, link = struct.unpack(endian + 'HHIIII', header[4:])
            if (major, minor) != (2, 4) or link != 127 or not 8 <= snaplen <= 262144:
                raise ValueError('Unsupported capture version, link metadata or snapshot length')
            self.endian, self.precision, self.snaplen = endian, precision, snaplen
            self.offset = 24
        header = self._take(16)
        if header is None:
            return None
        seconds, fraction, size, original = struct.unpack(self.endian + 'IIII', header)
        if size != original or not 8 <= size <= self.snaplen or fraction >= self.precision:
            raise ValueError('Invalid or snapshot-truncated pcap record')
        complete = self._take(16 + size)
        if complete is None:
            return None
        frame = decode_radiotap(complete[16:], self.stats)
        self.offset += 16 + size
        self.index += 1
        self.stats['pcap_records'] = self.index
        return self.index, seconds + fraction / self.precision, frame

    def finish(self):
        """Validate final EOF after the producer has stopped and records drained."""
        if self.failed or self.endian is None or self.offset != os.fstat(self.stream.fileno()).st_size:
            raise ValueError('Capture not fully drained or has an incomplete final record')

    def close(self):
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class CaptureTransport:
    """Bridge a prepared capture and bounded submission callback to the runner.

    not_before is a capture-clock cutoff established by the caller at admission.
    clock/sleep use a separate monotonic delivery clock, as does the session.
    The caller owns capture startup/shutdown and the reader's lifetime.
    """
    def __init__(self, capture, submit, *, not_before, clock, sleep, ready=None, after_record_index=0):
        if type(not_before) not in (int, float) or not math.isfinite(not_before) or not_before < 0:
            raise ValueError('Finite capture-clock cutoff required')
        if type(after_record_index) is not int or after_record_index < 0:
            raise ValueError('Nonnegative capture record cursor required')
        self.after_record_index = after_record_index
        self.capture, self._submit = capture, submit
        self.not_before, self.clock, self.sleep = not_before, clock, sleep
        self.last_record, self.last_capture_time = None, None
        self.capture_error = None
        self._ready = ready

    def receive(self, timeout):
        if self.capture_error is not None:
            raise OSError('Capture transport failed; a new context is required')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Positive finite receive timeout required')
        deadline = self.clock() + timeout
        for _ in range(64):
            if self._ready is not None:
                try:
                    self._ready()
                except OSError:
                    self.capture_error = 'capture_producer_unavailable'
                    raise
            if self.clock() >= deadline:
                return None
            try:
                record = self.capture.next_record()
            except (ValueError, OSError) as exc:
                self.capture_error = 'capture_parse_or_io_failure'
                raise OSError('Capture context unavailable') from exc
            if record is None:
                self.sleep(min(.01, max(0, deadline - self.clock())))
                continue
            index, timestamp, frame = record
            if self.last_capture_time is not None and timestamp < self.last_capture_time:
                self.capture_error = 'capture_timestamp_regression'
                raise OSError('Capture clock context changed')
            self.last_capture_time = timestamp
            if frame is None or timestamp < self.not_before or index <= self.after_record_index:
                continue
            self.last_record = {
                'packet_index': index, 'capture_time': timestamp,
                'timestamp_source': 'pcap_record',
                'ap_receive_time_confirmed': False,
                'ap_signal_measurement_available': False,
            }
            return frame
        return None

    def submit(self, frame):
        return self._submit(frame)
