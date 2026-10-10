# Incremental capture input

`capture_stream.GrowingCapture` reads one opened, append-only classic pcap file. It consumes each complete record once, retaining the byte offset while an incomplete header or payload is pending. It uses the existing radiotap/FCS validator. A driver/software-rejected FCS record is consumed and counted but produces no frame. Parsing errors or an observed file shrink permanently fail the reader. It does not follow file rotation or detect every same-size overwrite; the producer must honor the append-only contract.

The supported format is pcap 2.4, radiotap link value exactly 127, either byte order and microsecond/nanosecond timestamps. Snapshot-truncated, oversized or invalid-fraction records are rejected. Additional link-header metadata and pcapng are unsupported. Pending EOF is not completion: after stopping the producer and draining records, `finish()` verifies no incomplete tail remains. The caller closes the reader.

`CaptureTransport` bridges this input to `run_handshake`. The caller supplies a bounded submission callback returning accepted raw-frame bytes, monotonic `clock`/`sleep`, and `not_before` in the pcap capture-clock domain. The capture cutoff prevents delivery of earlier buffered frames. It does not convert capture timestamps into session time. Clock domains must be explicitly aligned at admission by the caller. Capture time regression stops this context. Each receive call examines at most 64 records and uses finite polls; quality rejects and pre-cutoff records never reach the handshake state machine.

The runner associates each constructed response with the triggering input SHA-256 and delivery ordinal. When supplied by the transport, capture index/time are retained separately. These fields are traceability evidence, not cryptographic proof of sender identity or AP acceptance.

This module does not start tcpdump, open a raw socket or choose radios. Connecting the existing physical adapter also requires bounded submission, capture lifecycle ownership, correctly aligned admission/capture clocks, cleanup and independent final capture validation. The physical adapter returns an action object rather than the runner's byte-count contract; it must not be passed directly as the callback.

The subsequent `radio_handshake.PhysicalHandshakeTransport` now provides action-to-byte-count conversion, admission checks and producer-liveness checks. See `radio-handshake.md` for its current ownership and validation limits; complete live orchestration remains pending.

Offline validation covers partial writes, repeated reads, FCS rejection, shrink, incomplete EOF, capture cutoff, clock regression, corrupted lengths, both byte orders/precisions, and response-trigger provenance. Known fixture SNonce is used only in the historical handshake-reproduction test; arbitrary saved M3 cannot authenticate against a newly generated SNonce.
