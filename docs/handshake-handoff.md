# Association-to-handshake handoff

`ClockAnchor.sample()` brackets a same-host realtime clock sample with monotonic samples. The sampling bracket must be at most 50 ms; its midpoint is used for mapping and half-width retained as uncertainty. The caller samples before the association exchange. Later checks reject a changed realtime/monotonic relationship greater than 50 ms plus sampling uncertainty. These are platform tolerances, not IEEE protocol timing rules or an assertion of synchronized external hardware.

`prepare_handoff(adapter, association, advertisement, pmk, anchor)` requires an already running independent capture. It copies a bounded prefix of the current pcap (maximum 32 MiB) to a temporary snapshot, validates complete records and keeps at most 4096 recent accepted frames. An incomplete final record is pending; it is not admitted as a packet. The original file remains available for continued reading.

Capture timestamps are mapped into the session's monotonic domain for freshness and association admission. Original pcap indexes and capture timestamps are also retained, together with the anchor and capture quality. The caller declares that the pcap uses the same host realtime clock; the mapping is not independently attested and must not be used for arbitrary remote pcaps.

After checking the entire observed snapshot for contradictory responses or boundaries, the transport cursor starts after the **first** matching success response. This preserves M1 already captured after that response, even if a duplicate association response follows M1. It also handles equal-timestamp request/response/M1 ordering by record index. The reader scans the original file from its start but does not deliver pre-cursor records to the session. Time filtering and cursor filtering are both required.

The returned physical bridge rechecks clock consistency during receive polls and before response submission. The returned session starts its deadline in monotonic time. Close the returned bridge to close its reader; adapter startup, final capture shutdown, reporting and cleanup remain the caller's responsibility. This helper itself submits no frame.

Tests cover distinct epoch/monotonic origins, buffered equal-time M1, response retry ordering, partial M1 append, clock sampling bounds, clock jumps before and after handoff, and a disconnect after association success. Full suite: 186 tests passed on 2026-10-10. Complete live CLI and Linux hardware validation remain pending.

Subsequent integration: `hotspot_cli` now exposes the `handshake` command and uses this helper. See `handshake-command.md`; command-level simulation has passed, while Linux hardware validation remains pending.
