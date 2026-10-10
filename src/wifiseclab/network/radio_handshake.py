"""Bridge an explicitly prepared dual-radio adapter to initial WPA2 decisions."""
import hashlib
import time
from wifiseclab.network.capture_stream import GrowingCapture, CaptureTransport
from ..protocol.eapol import decode_key


class PhysicalHandshakeTransport(CaptureTransport):
    def __init__(self, adapter, session, *, not_before, clock=time.monotonic, sleep=time.sleep,
                 after_record_index=0, clock_guard=None):
        evidence = getattr(session, 'admission_evidence', None)
        if (not evidence or evidence.get('eligible') is not True or
                evidence.get('bssid') != session.bssid or evidence.get('station') != session.station):
            raise ValueError('Captured association admission required for physical handshake transport')
        self.adapter, self.session = adapter, session
        self._clock_guard = clock_guard
        self.submission_actions = []
        self.submission_failed, self.attempted_hashes = False, set()
        self._ensure_ready()
        # Validate the clock cutoff before opening the owned reader.
        super().__init__(None, self._submit_response, not_before=not_before,
                         clock=clock, sleep=sleep, ready=self._ensure_ready,
                         after_record_index=after_record_index)
        self.capture = GrowingCapture(adapter.output / 'air.pcap')

    def _ensure_ready(self):
        if (not self.adapter.active or self.adapter.capture is None or
                self.adapter.capture.poll() is not None):
            raise OSError('Independent capture producer is unavailable')
        if self._clock_guard is not None:
            try:
                self._clock_guard()
            except (ValueError, OSError) as exc:
                raise OSError('Capture clock relationship is unavailable') from exc

    def _submit_response(self, frame):
        self._ensure_ready()
        if self.capture_error is not None or self.capture.failed or self.submission_failed:
            raise OSError('Capture context failed')
        if not self.session.tick(self.clock()):
            raise OSError('Handshake session is terminal')
        key = decode_key(frame, self.session.bssid, self.session.station)
        if key is None or key['message'] not in (2, 4) or key['issues']:
            raise ValueError('Expected a validated initial handshake response for this peer')
        expected_hash = hashlib.sha256(frame).hexdigest()
        if not any(event.get('decision') == 'response_constructed' and
                   event.get('frame_sha256') == expected_hash for event in self.session.events):
            raise ValueError('Response was not constructed by this session')
        if expected_hash in self.attempted_hashes:
            raise OSError('Response submission already attempted')
        self.attempted_hashes.add(expected_hash)
        self.submission_failed = True
        try:
            action_index = len(self.adapter.actions)
            action = self.adapter.send(frame)
        except (OSError, RuntimeError) as exc:
            raise OSError('Physical response submission failed') from exc
        if (not isinstance(action, dict) or action.get('kind') != 'frame_submitted' or
                type(action.get('bytes')) is not int or action['bytes'] != len(frame) or
                action.get('sha256') != expected_hash or
                len(self.adapter.actions) != action_index + 1 or self.adapter.actions[-1] is not action):
            raise OSError('Physical submission evidence contract mismatch')
        self.submission_actions.append({'frame_sha256': expected_hash,
                                        'adapter_action_index': action_index})
        self.submission_failed = False
        return len(frame)

    def close(self):
        self.capture.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
