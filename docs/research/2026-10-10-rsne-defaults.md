# RSNE trailing omissions and effective defaults

Read IEEE 802.11-2020 printed pages 1050–1053 (9.4.2.24.1–2 and opening of .3), the default-AKM paragraph on 1056, capabilities introduction and field description on 1057, and PMKID clause on 1059. Some intervening table extraction was truncated; this record does not claim the complete AKM table or all capability semantics were read. Source is the previously recorded cached 2020 mirror, not the current 2024 edition.

Version is mandatory. Subsequent nonzero-length fields may be omitted only as a trailing sequence; a partial field is not an omission. Pairwise and AKM counts of zero are reserved, while a PMKID count of zero is meaningful and permits a following group-management selector. Non-DMG omitted data ciphers default to CCMP-128; omitted AKM defaults to 802.1X, not PSK. Omitted capabilities default to zero. For the advertised MFPC context, an omitted group-management selector is reported as BIP-CMAC-128; this does not prove PMF was negotiated.

`rsn_details` previously rejected a version-only RSNE, a complete group-only RSNE and an omitted AKM list. It now distinguishes complete boundary omissions from truncation, reports which effective fields used defaults, preserves raw RSNE bytes, and withholds effective fields when parsing fails. Its default context is explicitly non-DMG; DMG defaults are not inferred from this parser.

This is parsing, not negotiation or full semantic validity. Unknown selectors remain visible; unsupported active profiles still fail their separate checks. Exact M2 association binding and M3 advertisement binding retain raw-byte comparisons; semantic equality must not erase a wire mismatch. Existing construction restrictions are not silently widened.

Regression tests cover every complete mandatory-field boundary, partial fields, reserved counts, PMKID lengths, default/explicit management ciphers, raw-byte preservation and refusal to treat omitted AKM as PSK. Full suite: 179 tests passed on 2026-10-10. No wireless activity.
