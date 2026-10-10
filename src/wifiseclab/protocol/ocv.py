"""OCI consistency against an explicitly supplied peer-link snapshot.

No OCV negotiation, integrity, snapshot freshness or AP acceptance inference.
"""
from wifiseclab.protocol.operating_classes import global_class_reference


def compare_oci_channel(oci, link):
    result = dict(channel_validation="unknown", mismatches=[], missing=[],
                  receiver_acceptance_confirmed=False,
                  evidence_scope="Caller-bound channel snapshot comparison only")
    if oci is None:
        result["missing"].append("OCI")
        return result
    if not isinstance(oci, dict) or not isinstance(link, dict):
        raise ValueError("OCI and link snapshot must be objects")
    for name in ("operating_class", "primary_channel", "frequency_segment_1"):
        if type(oci.get(name)) is not int or not 0 <= oci[name] <= 255:
            raise ValueError("Expected octet OCI fields")
    reference = global_class_reference(oci["operating_class"])
    if reference is None or oci["operating_class"] == 82:
        result["missing"].append("supported PHY/class interpretation")
        return result
    width = reference["channel_spacing_mhz"]
    # Class 81 reference spacing is 25; this checker is for OFDM 20 MHz.
    if oci["operating_class"] == 81:
        if link.get("phy_profile") != "ofdm":
            result["missing"].append("explicit OFDM profile for class 81")
            return result
        width = 20
    channels = reference["channel_set"]
    centers = reference["center_frequency_indices"]
    primary = oci["primary_channel"]
    candidates = []
    if channels is not None:
        allowed = primary in channels
    else:
        span = width // 10 - 2
        candidates = [c for c in centers if primary in range(c - span, c + span + 1, 4)]
        allowed = len(candidates) == 1
    if not allowed:
        result["mismatches"].append("primary channel outside class")
    start = reference["channel_starting_frequency_mhz"]
    primary_frequency = start + primary * 5
    frequency = link.get("primary_frequency_mhz")
    if type(frequency) is not int or frequency <= 0:
        result["missing"].append("primary_frequency_mhz")
    elif frequency != primary_frequency:
        result["mismatches"].append("primary frequency")
    local_width = link.get("max_width_mhz")
    noncontiguous = link.get("noncontiguous_80_plus_80")
    if type(noncontiguous) is not bool:
        result["missing"].append("noncontiguous_80_plus_80")
    if type(local_width) is not int or local_width not in (20, 40, 80, 160):
        result["missing"].append("supported max_width_mhz")
    else:
        if noncontiguous is True and local_width != 160:
            raise ValueError("80+80 snapshot requires aggregate max_width_mhz=160")
        advertised_width = 160 if reference["noncontiguous_80_plus_80"] else width
        if local_width > advertised_width:
            result["mismatches"].append("maximum bandwidth exceeds OCI")
        if noncontiguous is True and (local_width != 160 or not reference["noncontiguous_80_plus_80"]):
            result["mismatches"].append("80+80 topology")
        if (local_width == 160 and noncontiguous is False
                and reference["noncontiguous_80_plus_80"]):
            result["missing"].append("contiguous 160 versus 80+80 spectral compatibility")
        if local_width == 40:
            position = reference["primary_position"]
            offset = 1 if position == "lower" else -1 if position == "upper" else None
            if offset is None and candidates:
                span = width // 10 - 2
                index = (primary - (candidates[0] - span)) // 4
                offset = 1 if index % 2 == 0 else -1
            supplied = link.get("secondary20_offset")
            if type(supplied) is not int or supplied not in (-1, 1) or offset is None:
                result["missing"].append("40 MHz secondary channel interpretation")
            elif supplied != offset:
                result["mismatches"].append("40 MHz secondary direction")
    segment = oci["frequency_segment_1"]
    if reference["noncontiguous_80_plus_80"]:
        if segment not in centers or candidates and abs(segment - candidates[0]) <= 16:
            result["mismatches"].append("invalid noncontiguous segment 1")
        if noncontiguous is True:
            supplied = link.get("segment1_frequency_mhz")
            if type(supplied) is not int:
                result["missing"].append("segment1_frequency_mhz")
            elif supplied != start + segment * 5:
                result["mismatches"].append("segment 1 frequency")
    elif segment != 0:
        result["mismatches"].append("unexpected segment 1")
    if oci.get("oct_present"):
        result["missing"].append("independent OCT channel comparison")
    result["channel_validation"] = ("inconsistent" if result["mismatches"] else
                                      "unknown" if result["missing"] else "consistent")
    return result
