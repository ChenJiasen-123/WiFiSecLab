"""Evidence-based lifecycle controller, separate from unobserved key state."""
from enum import Enum
import re
from ..network.hotspot import mac_bytes, mac_text

class Stage(str, Enum):
    READY = "ready"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"
    DONE = "done"


def fields(text):
    if not isinstance(text, str):
        raise ValueError("control response must be text")
    result = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ValueError("empty or duplicate control field")
        result[key] = value
    return result


def station_flags(text, peer):
    # 必须核对响应中的客户端 MAC；不能把其他客户端的授权状态套到当前会话。
    if not isinstance(text, str) or not isinstance(peer, str):
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip().lower() != peer.lower():
        return None
    try:
        flags = fields(text).get("flags")
    except ValueError:
        return None
    if flags is None or re.fullmatch(r"(?:\[[A-Za-z0-9_]+\])*", flags) is None:
        return None
    return flags


class Lifecycle:
    def __init__(self, profile, akm, *, bssid, station):
        ap, sta = mac_bytes(bssid), mac_bytes(station)
        if ap == sta:
            raise ValueError("Distinct AP and STA identities required")
        self.bssid, self.station = mac_text(ap), mac_text(sta)
        self.profile, self.akm = profile, akm
        self.stage = Stage.READY
        self.session = 0
        self.timeline = []
        self.findings = []
        self.unknown = ["stable key identity and counter continuity", "driver/firmware key deletion", "pending queue and timer cleanup", "old-session input isolation"]

    def action(self, action, evidence):
        table = {(Stage.READY, "connect"): Stage.CONNECTING,
                 (Stage.CONNECTED, "disconnect"): Stage.DISCONNECTING,
                 (Stage.DISCONNECTED, "reconnect"): Stage.RECONNECTING}
        if (self.stage, action) not in table:
            raise ValueError(f"action {action} invalid at {self.stage.value}")
        before = self.stage
        self.stage = table[(self.stage, action)]
        if action in {"connect", "reconnect"}:
            self.session += 1
        self.timeline.append(dict(type="action", action=action, before=before.value,
                                  after=self.stage.value, session=self.session, evidence=evidence))

    def observe(self, sta_status, ap_station, peer, evidence):
        try:
            sta = fields(sta_status)
            sta_valid = True
        except ValueError:
            sta, sta_valid = {}, False
        peer_matches = isinstance(peer, str) and peer.lower() == self.station
        flags = station_flags(ap_station, self.station) if peer_matches else None
        def matches(field, expected):
            try:
                return mac_text(mac_bytes(sta.get(field))) == expected
            except ValueError:
                return False
        station_matches = matches("address", self.station)
        bssid_matches = matches("bssid", self.bssid)
        associated = flags is not None and "[ASSOC]" in flags
        authorized = flags is not None and "[AUTHORIZED]" in flags
        removed = peer_matches and isinstance(ap_station, str) and ap_station.strip() == "FAIL"
        completed = sta.get("wpa_state") == "COMPLETED"
        cipher_matches = (sta.get("pairwise_cipher") == "CCMP" and
                          sta.get("group_cipher") == "CCMP")
        before = self.stage
        connection = (peer_matches and station_matches and bssid_matches
                      and completed and cipher_matches and associated and authorized and "[AUTH]" in (flags or "")
                      and sta.get("key_mgmt") == self.akm)
        if self.akm == "SAE":
            connection = connection and "[MFP]" in (flags or "") and sta.get("pmf") in {"1", "2"}
        if self.stage in {Stage.CONNECTING, Stage.RECONNECTING} and connection:
            self.stage = Stage.CONNECTED if self.stage == Stage.CONNECTING else Stage.DONE
        elif self.stage == Stage.DISCONNECTING:
            disconnected = (peer_matches and station_matches
                            and sta.get("wpa_state") == "DISCONNECTED")
            if disconnected and (removed or (flags is not None and not associated and not authorized)):
                self.stage = Stage.DISCONNECTED
        self.timeline.append(dict(type="observation", before=before.value, after=self.stage.value,
            session=self.session, peer=peer, evidence=evidence,
            facts=dict(sta_response_valid=sta_valid,
                       target_peer_matches=peer_matches,
                       station_address_matches=station_matches, bssid_matches=bssid_matches,
                       ap_response_valid=flags is not None or removed,
                       sta_state=sta.get("wpa_state"), associated=associated,
                       authorized=authorized, station_removed=removed,
                       key_mgmt=sta.get("key_mgmt"), pmf=sta.get("pmf"),
                       pairwise_cipher=sta.get("pairwise_cipher"),
                       group_cipher=sta.get("group_cipher"), cipher_profile_matches=cipher_matches)))
        return self.stage != before

    def timeout(self, evidence):
        self.findings.append(dict(code="LIFECYCLE_TIMEOUT", stage=self.stage.value,
                                  evidence=evidence, detail="expected transition not confirmed within budget; not a vulnerability verdict"))

    def report(self):
        return dict(profile=self.profile, stage=self.stage.value,
            target_bssid=self.bssid, target_station=self.station,
            required_pairwise_cipher="CCMP", required_group_cipher="CCMP",
            passed=self.stage == Stage.DONE and not self.findings,
            session_count=self.session, findings=self.findings,
            unverified=self.unknown, timeline=self.timeline,
            scope="AP control-interface lifecycle checks; no claim of key deletion or nonce safety")
