# Receive-driven handshake runner

`wifiseclab.network.handshake_runner.run_handshake(session, transport, clock)` drives an existing `HandshakeSession`. The caller owns association acceptance, selected advertisement, PMK, transport setup and cleanup. The runner does not open a radio or select an interface.

Transport contract:

- `receive(timeout)` returns one raw 802.11 frame as bytes, without radiotap/FCS, or `None`. The adapter must honor the finite timeout and perform capture-quality validation before delivery.
- `submit(frame)` returns the byte count accepted by the transport. It must have a bounded execution time. A full count proves only API acceptance.
- `clock()` returns finite monotonic time using the same origin as the session's `started_at`.

The loop validates session time before receiving, after receiving, and after response construction before submission. It continues receiving after M4 so retransmission decisions remain possible until the session expires. Defaults are 100 ms receive polls and at most 4096 polls; the session independently caps time and constructed responses. This synchronous function cannot preempt an adapter that violates its timeout contract.

Receive and submission OS errors produce stop reasons without including exception text. Partial, invalid or unknown submission counts stop the run without automatic retry: an uncertain send must not create an untracked duplicate. Invalid transport frame types also stop the run. Programming errors propagate for diagnosis; they are not converted into AP verdicts.

The report separates constructed responses from transport submissions and their byte counts. It never asserts over-air transmission, AP authorization, or key installation. Independent capture correlation and AP instrumentation are required for those claims. The nested session's `transmitted: false` describes the constructor, not an assertion that an externally supplied transport was passive.

Validation uses an in-memory AP peer that verifies generated M2 MIC, constructs M3 for the received fresh SNonce, and verifies M4 MIC. Additional cases cover incomplete/unknown sends, exceptions, late receive, slow construction, and a nonadvancing empty receiver. This proves the orchestration path in simulation. Existing physical transport has not yet been wired to this runner or validated with custom M2/M4 over radio.
