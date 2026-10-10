# Offline WPA2 M2 construction

`wifiseclab.protocol.wpa2.build_m2(m1, association, pmk, snonce=None, sequence=0, eapol_version=2)` returns one raw 802.11 Data frame containing an EAPOL M2. Inputs are raw frames without radiotap/FCS and a single known 32-byte PMK. It performs no transmission, password search or AP state inference. The default SNonce uses the operating system random source.

The supported profile is legacy WPA2 PSK with CCMP, a single selected AKM/cipher, zero RSN capabilities, and no PMF/RSNXE. M1 must match the association AP/STA identities and profile. The response copies its replay counter, uses the association RSNE, derives the KCK from both MAC addresses and nonces, and computes the descriptor-version-2 MIC. Unsupported profiles and malformed inputs raise an error.

The offline transcript analyzer retains multiple observed SNonce candidates. With the configured PMK, M3 MIC validation selects a candidate; M4 is checked using the candidate associated with its M3 counter. Without cryptographic binding, multiple candidates are reported as ambiguous.

`build_m4(m1, m2, m3, association, advertisement, pmk, sequence=0, eapol_version=2)` constructs a normal initial-handshake M4 only after validating one supplied branch: M2 equals the selected M1/association response, M3 nonce/counter and MIC match, AES unwrap and baseline Key Data checks pass, and the first M3 RSNE equals a compatible AP advertisement. The advertisement SSID must match the association. M4 copies M3's counter, uses zero nonce/key length/key data and sets Secure/MIC/Pairwise. The API does not maintain packet arrival order, freshness or previous replies: it cannot decide when replaying a stored M3 is appropriate. It performs no transmission or key installation.

Formal offline commands (raw 802.11 input/output without radiotap or FCS):

```bash
python3 tools/protocol/wpa2_build.py m2 --m1 m1.bin --association assoc.bin --pmk-file lab-pmk.bin --output m2-new.bin
python3 tools/protocol/wpa2_build.py m4 --m1 m1.bin --m2 m2.bin --m3 m3.bin --association assoc.bin --advertisement beacon.bin --pmk-file lab-pmk.bin --output m4-new.bin
```

Installed command: `wifiseclab-wpa2-build`. M4 requires `pip install '.[crypto]'`. Files and their containing directory must already be provided except the new output file, which must not exist. The M2 CLI generates a fresh SNonce; preserve that generated M2 as the input to the later M4 step. Stdout contains frame metadata, not PMK/KCK/KEK. Input packets are not obtained or transmitted by this command.

133 project tests pass, including byte-exact comparison of generated EAPOL M4 with an independently captured isolated hwsim sample, an offline analyzed path containing the generated M4, negative context/identity/MIC cases, and CLI no-overwrite. This is not evidence of a completed active custom-client handshake.

Validation: an independently captured isolated hwsim M2 is reproduced byte-for-byte at the EAPOL layer with its captured SNonce and EAPOL version. A synthetic retry scenario checks selection of an earlier SNonce after a later M2. These checks do not establish AP key installation, GTK unwrap, RSNE consistency, data authorization or a complete active handshake. This constructor is intentionally not connected to the live radio flow.
