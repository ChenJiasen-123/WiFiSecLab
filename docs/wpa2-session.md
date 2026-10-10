# Offline WPA2 handshake session controller

`wifiseclab.protocol.wpa2_session.HandshakeSession` connects the M2/M4 constructors to bounded receive-driven decisions for initial WPA2 PSK/CCMP handshakes. It accepts raw 802.11 frames without radiotap or FCS. It never transmits frames or installs keys.

Create a session with the station association request, the selected AP advertisement, and one known 32-byte PMK. The caller must separately establish association acceptance and select the correct peer context. `receive(frame, now)` returns at most one response frame or `None`; `tick(now)` checks expiry, and `report()` returns decisions without the PMK or GTK. Times must be finite and monotonic, relative to the same origin as `started_at`.

The first valid M1 creates an SNonce. Same-ANonce retries reuse that SNonce; a repeated M1 counter produces no additional response. An unauthenticated M1 counter does not advance authenticated replay history. M3 must match an eligible earlier M1 branch and pass MIC, wrapped-key integrity, key-data and AP advertisement validation before M4 is constructed. Only a validated M3 advances authenticated replay history. A fresh-counter M3 retry may receive another M4; duplicate or older authenticated counters are ignored. No key installation occurs on either path.

The controller defaults to a 10-second deadline and eight constructed responses, with configurable limits of 60 seconds and 32 responses. Expiry and exhausted budget terminate the session. Matching authentication, association, disassociation or deauthentication management boundaries, and unsupported EAPOL context, require a new session. Changed ANonce and M1 after M4 are rejected without replacing existing history; the caller must explicitly establish a new session. These are conservative controller policies, not vulnerability verdicts or universal protocol compliance rules.

`m4_constructed` means local response construction succeeded. It does not prove AP acceptance, authorization, key installation, encrypted data connectivity, or resistance to key reinstallation. Rekey, SAE, FT, PMF and live transport integration remain separate work.

Tests include captured-frame reproduction with a fixed test SNonce, a different SNonce with a newly signed and wrapped synthetic M3, counter poisoning attempts, invalid MIC, retries, timeout, budget and context discontinuity. They are offline tests and provide no new over-the-air evidence.
