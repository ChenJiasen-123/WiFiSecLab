"""Selected global classes from IEEE 802.11-2024 Table E-4, pp.5658-5662.

Reference data only. Channel spacing is not silently converted to PHY bandwidth.
Not a regulatory authorization database or an OCV conformance decision.
"""

# starting MHz, spacing MHz, direct channel set, center indices, primary position,
# noncontiguous 80+80. None indicates a column not specified by this row.
_ROWS = {
    81: (2407, 25, range(1, 14), None, None, False),
    82: (2414, 25, (14,), None, None, False),
    83: (2407, 40, range(1, 10), None, "lower", False),
    84: (2407, 40, range(5, 14), None, "upper", False),
    115: (5000, 20, (36, 40, 44, 48), None, None, False),
    116: (5000, 40, (36, 44), None, "lower", False),
    117: (5000, 40, (40, 48), None, "upper", False),
    118: (5000, 20, (52, 56, 60, 64), None, None, False),
    119: (5000, 40, (52, 60), None, "lower", False),
    120: (5000, 40, (56, 64), None, "upper", False),
    121: (5000, 20, range(100, 145, 4), None, None, False),
    122: (5000, 40, range(100, 141, 8), None, "lower", False),
    123: (5000, 40, range(104, 145, 8), None, "upper", False),
    124: (5000, 20, (149, 153, 157, 161), None, None, False),
    125: (5000, 20, range(149, 178, 4), None, None, False),
    126: (5000, 40, (149, 157, 165, 173), None, "lower", False),
    127: (5000, 40, (153, 161, 169, 177), None, "upper", False),
    128: (5000, 80, None, (42, 58, 106, 122, 138, 155, 171), None, False),
    129: (5000, 160, None, (50, 114, 163), None, False),
    130: (5000, 80, None, (42, 58, 106, 122, 138, 155, 171), None, True),
    131: (5950, 20, range(1, 234, 4), None, None, False),
    132: (5950, 40, None, range(3, 228, 8), None, False),
    133: (5950, 80, None, range(7, 216, 16), None, False),
    134: (5950, 160, None, range(15, 208, 32), None, False),
    135: (5950, 80, None, range(7, 216, 16), None, True),
    136: (5925, 20, None, (2,), None, False),
}


def global_class_reference(class_id):
    if type(class_id) is not int or not 0 <= class_id <= 255:
        raise ValueError("Operating class must be an octet")
    row = _ROWS.get(class_id)
    if row is None:
        return None  # Unsupported does not mean reserved or invalid.
    start, spacing, channels, centers, position, noncontiguous = row
    return dict(source="IEEE 802.11-2024 Table E-4 selected rows",
                channel_starting_frequency_mhz=start,
                channel_spacing_mhz=spacing,
                channel_set=list(channels) if channels is not None else None,
                center_frequency_indices=list(centers) if centers is not None else None,
                primary_position=position, noncontiguous_80_plus_80=noncontiguous,
                phy_bandwidth_validated=False, regulatory_permission_confirmed=False)
