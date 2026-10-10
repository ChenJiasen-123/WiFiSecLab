"""Parse explicit hostapd events; never infer key installation from handshake."""
import re

def parse_log(text, evidence="hostapd.log"):
    events=[]
    patterns=[("peer_connected", r"AP-STA-CONNECTED ([0-9a-fA-F:]{17})"),
              ("peer_disconnected", r"AP-STA-DISCONNECTED ([0-9a-fA-F:]{17})"),
              ("pairwise_handshake_completed", r"STA ([0-9a-fA-F:]{17}) WPA: pairwise key handshake completed")]
    for line_number,line in enumerate(text.splitlines(),1):
        for kind,pattern in patterns:
            match=re.search(pattern,line)
            if match:
                events.append(dict(kind=kind,peer=match.group(1).lower(),source="hostapd_log",
                                   evidence=f"{evidence}:{line_number}",raw=line))
    return events
