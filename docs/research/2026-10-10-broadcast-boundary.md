# AP broadcast disconnect observation boundary

Read IEEE 802.11-2020 printed page 828, clause 9.3.3.4/Table 9-33, plus surrounding printed page 829. The disassociation body contains a Reason Code and may carry an MME for group-addressed protection. This is a frame-format reading, not a completed PMF receive-procedure review.

Found a shared observation defect: passive EAPOL correlation, handshake response decisions and association admission considered only the exact AP/STA unicast pair. An AP-source/BSSID broadcast disconnect could therefore leave old context active. A shared `disconnect_affects_peer()` address-scope helper now includes AP broadcast disassociation and deauthentication. It also retains both unicast directions. Other multicast membership, protected unicast decryption, MMIE authentication and replay checks remain outside scope.

The resulting stop is conservative observation policy. An unauthenticated or spoofed disconnect does not prove AP or STA accepted it, changed state, or reset keys. The platform must not claim PMF bypass from this boundary.

Tests cover broadcast subtypes 10 and 12 in all three consumers, plus wrong source, BSSID and station destination in passive analysis. Complete suite: 157 tests passed on 2026-10-10.

The capture-backed association gate was additionally run on existing isolated hwsim WPA2 and transition-PSK pcaps. Both first request-through-response windows were eligible. The generated report retains original pcap record bounds, SHA-256 hashes and capture-quality counts. This validates historical association response correlation only; it is not a new custom handshake or physical-radio experiment. It does not establish absence of later contradictory frames or AP internal state.
