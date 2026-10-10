# Prepared physical-adapter handshake bridge

`radio_handshake.PhysicalHandshakeTransport` adapts an already running `PhysicalRadioAdapter` to `run_handshake`. It requires a session created through captured association admission and an explicit `not_before` cutoff in the capture clock domain. It opens an incremental reader of the adapter's independent `air.pcap`; it does not create monitor interfaces, change channels, start authentication/association, or start tcpdump.

Every receive poll checks capture-process availability. Capture exit invalidates the transport even if frames remain buffered; remaining records may be evaluated separately during final offline analysis. Only locally constructed M2/M4 frames for this session may be submitted. The bridge checks action kind, raw byte count, frame hash and the newly appended adapter action. It converts successful action evidence to the runner's byte-count contract and retains the adapter action index.

Each constructed frame has at most one application submission attempt through a bridge instance. Uncertain submission failure permanently disables further submissions through that instance. Fresh-counter handshake retries produce new constructor output; driver retries remain separate. Capture errors, session expiry and producer exit prevent submission.

`PhysicalRadioAdapter` now applies a socket timeout before bind/send; default 0.5 seconds, configurable in `(0, 2]`. This bounds timeout-aware socket I/O, not every possible native/kernel stall or complete setup/teardown runtime. No automatic retransmission is added. Socket timeout and short write remain uncertain submission outcomes, not proof that nothing reached the medium.

Ownership: the caller prepares and cleans up the adapter. Closing the bridge closes only its reader. After the run, stop the capture producer, drain/validate the final pcap separately, produce the physical report and collect independent AP state evidence. The capture clock cutoff must correspond to the admitted exchange; session time remains monotonic. A complete live command integrating clock alignment, lifecycle and final evidence is not yet implemented.

Validation uses the actual adapter's send code with a mocked AF_PACKET socket and a simulated AP that appends M3 for each generated SNonce. It covers M2/M4 verification, timeout, short write, capture exit, missing admission, invalid outgoing direction, bounded timeout configuration and duplicate submission attempts. No Linux radio was used in this validation. Capture observation, AP acceptance, authorization and key installation remain separate claims.

`handshake_handoff.prepare_handoff` subsequently supplies bounded capture snapshots, clock binding and a record cursor that preserves buffered M1. See `handshake-handoff.md`. It does not complete command-level capture setup, authentication/association execution, final evidence collection or hardware validation.
