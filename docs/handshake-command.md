# Known-PMK initial handshake command

The Linux/root command `wifiseclab-hotspot handshake` connects existing discovery, Open System authentication, association admission, capture handoff, receive-driven M2/M4 construction and final capture analysis. It uses the explicitly selected SSID/BSSID/channel and one known PMK. No password search, rekey campaign, malformed-frame mutation or key installation is performed by this command.

Example for a configured lab AP, replacing all example values:

```sh
sudo wifiseclab-hotspot handshake \
  --ssid 'YOUR_LAB_SSID' --bssid 02:00:00:00:00:01 --channel 1 \
  --pmk-file /path/known.pmk --output /path/new-evidence --duration 4
```

The PMK file must contain exactly 32 raw bytes, not hex text or a passphrase. Install the `crypto` extra. PMK length and dependency availability are checked before radio setup. The PMK is not written into reports. The evidence directory must be new; existing NetworkGuard and adapter context managers own restoration and cleanup.

The command selects a current baseline beacon for M3 parameter binding, sends one application authentication request, then one association request only after an observed successful authentication response. It polls for stage results rather than sleeping the full stage duration. Captured association evidence and a clock anchor gate the next stage; buffered M1 is preserved. The default handshake budget is eight constructed responses. Driver retries remain independent.

After handshake reception ends, capture stops and final strict parsing rechecks both earlier stages. The final EAPOL analysis uses the known PMK and key-data unwrap. A success exit requires confirmed final stage response consistency, locally constructed/submitted M4, successful transport submissions and a finalized RSNE-bound MIC-verified captured handshake path. It does not prove the AP accepted M4, installed keys, authorized data, or supports encrypted connectivity. Timeout/silence cannot establish a vulnerability.

`hotspot-report.json` contains the stage evidence, handshake decisions/submissions and final EAPOL analysis. The physical report remains independent. A later conflicting association response prevents success even if the captured four-message path passes cryptographic checks.

Validation: command-level simulations cover a fresh-SNonce full path, capture-process exit, final contradictory association evidence and invalid PMK before setup. Full suite: 190 tests passed on 2026-10-10. Hardware execution and behavior such as monitor-interface ACK handling remain unverified; this document does not claim a successful physical-radio handshake.
