# Replay history and unauthenticated M1

Read the cached IEEE 802.11-2020 text, clause 12.7.2(d), together with 12.7.6.2–5. The replay-history update is conditioned on MIC validation; M1 has no MIC and must not establish the authenticated receive floor. M2 responds to an outstanding M1; M3 and M4 retain distinct peer and branch constraints. This reading covers these clauses, not the whole standard or the current 2024 edition.

Also read the full two short primary-source reflector messages dated 2026-01-05:

- https://www.ieee802.org/11/email/stds-802-11-tgm/msg03789.html — proposed clarification of authenticated receive history.
- https://www.ieee802.org/11/email/stds-802-11-tgm/msg03788.html — discussion of whether M3 must be exactly one greater than M1, including retries.

These are working-group discussions and proposals, not proof of adopted normative changes. The analyzer does not impose an exact +1 requirement.

## Implementation correction

Previously, passive M3 correlation required its counter to exceed every observed M1 counter. A high unanswered M1 could therefore invalidate an otherwise complete earlier branch. The analyzer now records M2 counters by SNonce, selects a cryptographically matched branch when the PMK is supplied, and requires an earlier matching M1/M2 branch plus increasing prior accepted M3 history. Without PMK, multiple SNonce candidates remain ambiguous; counter feasibility alone does not select a branch.

This is a capture-consistency oracle, not a complete receiver state machine. Packet order, capture loss, authentication failures and ambiguous context remain separate observations; anomalies never prove AP misconduct. M2/M4 station-reply history is still checked separately. The active offline controller and passive analyzer now both avoid the unanswered-high-M1 poisoning case.

Regression tests cover the unanswered high M1 with and without a supplied PMK, and an authenticated M3 that precedes the selected M2 counter. Full suite: 142 tests passed on 2026-10-10. No radio transmissions were performed.
