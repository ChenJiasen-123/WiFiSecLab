# Capture-backed association admission

`association_gate.association_evidence()` accepts an initial association request and an ordered iterable of `(timestamp, raw_frame)` records. All times, including `now`, must use one monotonic clock domain. The default evidence window is two seconds, configurable up to ten seconds, with at most 4096 records. These are platform policy limits, not IEEE association timeout values.

It requires a recent independently observed request, allowing the existing matcher’s documented duration/retry/sequence rewrites. A response must follow that request in record order, use the expected AP source/BSSID and station destination, have status 0, a valid legacy AID, an infrastructure capability profile and Supported Rates. Trailing information elements must be structurally valid. It does not require an RSNE in an ordinary initial PSK response.

Repeated success responses with the same status and AID are accepted. Conflicting statuses or AIDs, malformed matching responses, and matching management session boundaries after the request prevent admission. Nonzero statuses are outside this initial-success profile; the code does not claim every nonzero status is a universal protocol failure. DMG, S1G, reassociation, FILS, FT and PMF negotiation are outside this gate's scope.

`admitted_session()` creates `HandshakeSession` only if the evidence is eligible. It starts the handshake deadline at the supplied `now` and retains admission evidence in the session report. The caller must provide the complete observed association window, separately perform Open System authentication, verify capture integrity, and retain any already queued EAPOL frames for subsequent delivery. A gate cannot discover omitted or lost packets. Direct construction of `HandshakeSession` remains available for offline tests; live orchestration should use the admission factory.

This gate supports evidence of a matching successful response, not cryptographic AP identity, AP internal association state, response ACK, authorization or key installation. Address and timing correlation alone cannot authenticate an AP. The physical transport is not connected to the new factory yet.

Tests cover success without RSNE, fresh/stale requests, wrong destination, response ordering, rejection, invalid AID, conflicting AID/status, duplicate retries, session boundaries, malformed/missing rates, invalid clocks and the record budget. The in-memory handshake runner demonstration now starts through this admission factory.
