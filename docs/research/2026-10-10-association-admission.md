# Association response format and admission boundary

Read the locally cached IEEE 802.11-2020 PDF's printed pages 831–834, clause 9.3.3.6 and Table 9-35, plus printed pages 873–874, clauses 9.4.1.8–9.4.1.9. PDF indexes used were 831–834 and 873–874 (the PDF physical page number is index + 1). The extraction includes surrounding table continuations, not a claim to have read all surrounding clauses.

The legacy association-response body contains Capability Information, Status Code, AID and Supported Rates. Table 9-35 makes RSNE presence conditional on FILS; ordinary initial PSK response admission must not require one. For non-DMG/non-S1G STAs, AID is 1–2007 in the low 14 bits with the two high bits set. Other PHY profiles have different AID rules. The status section also names SUCCESS_POWER_SAVE_MODE; the platform's status-0 gate is deliberately restricted to its initial legacy profile.

Online search also located historical IEEE draft association procedures, but they were not treated as the current standard or used to claim current-edition conformance. No new radio experiment or internal AP state observation was made.

Implementation: capture-backed admission factory with request/response ordering, finite freshness window, identity correlation, legacy response structure and contradictory/boundary evidence handling. This closes one orchestration gap while retaining the distinction between a captured response and verified AP state. Full tests: 154 passed on 2026-10-10.
