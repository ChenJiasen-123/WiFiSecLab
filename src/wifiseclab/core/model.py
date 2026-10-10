from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
from wifiseclab.core.stage_evidence import stage_evidence
from wifiseclab.lifecycle.group_delivery import GroupKeyDelivery
from wifiseclab.protocol.wnm import decode_sleep_response
from wifiseclab.protocol.ocv import compare_oci_channel

class Mode(str, Enum):
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    TRANSITION = "transition"

@dataclass
class Event:
    kind: str
    peer: str
    session: str
    source: str
    evidence: str
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw):
        e = cls(**raw)
        if not all(isinstance(x, str) and x.strip() for x in
                   (e.kind, e.peer, e.session, e.source, e.evidence)):
            raise ValueError("event identity and evidence must be nonempty strings")
        if e.source not in {"synthetic", "instrumentation", "pcap", "probe"}:
            raise ValueError("unknown source")
        if not isinstance(e.data, dict):
            raise ValueError("data must be an object")
        return e

@dataclass
class Peer:
    session: str
    auth: str = "none"
    akm: str | None = None
    associated: bool = False
    pmf: bool | None = None
    wnm_sleep: bool | None = None
    handshake: str = "idle"
    authorized: bool = False
    keys: dict[str, str] = field(default_factory=dict)
    pending: set[str] = field(default_factory=set)
    # Evidence stages, not a complete implementation of the SAE FSM.
    sae: str = "idle"
    sae_exchange: str | None = None
    exchange: str | None = None
    message: int = 0
    replay_counter: int | None = None
    m3_counters: set[int] = field(default_factory=set)
    accepted_response_counter: int | None = None
    cleanup_required: bool = False
    timers: set[str] = field(default_factory=set)

    def snapshot(self):
        # 覆盖率必须包括安全上下文；只看连接状态会漏掉残留密钥和定时器。
        return (self.auth, self.akm, self.associated, self.pmf, self.wnm_sleep, self.handshake,
                self.authorized, tuple(sorted(self.keys.items())),
                tuple(sorted(self.pending)), self.sae, self.sae_exchange, self.exchange,
                self.message, self.replay_counter, self.cleanup_required,
                tuple(sorted(self.timers)), tuple(sorted(self.m3_counters)),
                self.accepted_response_counter)

@dataclass
class Finding:
    code: str
    peer: str
    session: str
    evidence: str
    detail: str

class APModel:
    """Research abstraction. Internal events require instrumentation evidence.

    Session IDs are adapter-assigned. key_id identifies key material, not an
    installation attempt. Nonce domains must reflect the cipher's full domain.
    """
    def __init__(self, mode: Mode):
        self.mode = Mode(mode)
        self.peers = {}
        self.findings = []
        self.observations = []
        self.coverage = set()
        self.nonces = set()
        # Deleting a slot/session must not erase evidence of prior installation.
        self.key_installations = set()
        self.history = []
        self.sources = set()
        self.sessions = set()
        self.rx_counters = {}
        self.group_updates = {}
        self.abstractions = set()

    def flag(self, e, code, detail):
        self.findings.append(Finding(code, e.peer, e.session, e.evidence, detail))

    def apply(self, e: Event):
        # 先校验再更新，畸形输入不能留下半更新的状态。
        Event.parse(asdict(e))
        required = {"key_deleted": ("slot",),
                    "key_install_requested": ("slot",),
                    "key_delete_requested": ("slot",), "work_pending": ("work_id",),
                    "work_cleared": ("work_id",), "timer_started": ("timer_id",),
                    "timer_cancelled": ("timer_id",), "timer_expired": ("timer_id",),
                    "handshake_message": ("exchange_id",), "sae_commit_accepted": ("exchange_id",),
                    "sae_confirm_accepted": ("exchange_id",),
                    "data_accepted": ("key_id", "nonce_domain"),
                    "rx_counter_configured": ("key_id", "nonce_domain")}
        for name in required.get(e.kind, ()):
            if not isinstance(e.data.get(name), str) or not e.data[name].strip():
                raise ValueError(f"{e.kind} requires nonempty {name}")
        if e.kind in {"handshake_message", "data_accepted", "rx_counter_configured"}:
            name = "replay_counter" if e.kind == "handshake_message" else "pn"
            if type(e.data.get(name)) is not int or e.data[name] < 0:
                raise ValueError(f"{e.kind} requires nonnegative integer {name}")
        if e.kind == "handshake_message" and e.data["replay_counter"] >= 1 << 64:
            raise ValueError("EAPOL-Key Replay Counter exceeds its 8-octet field")
        if e.kind in {"data_accepted", "rx_counter_configured"}:
            cipher = e.data.get("cipher")
            if cipher in ("ccmp-128", "ccmp-256") and e.data["pn"] >= 1 << 48:
                raise ValueError("CCMP PN exceeds its 48-bit field")
        if e.kind == "handshake_message" and (type(e.data.get("message")) is not int or e.data["message"] not in (1, 2, 3, 4)):
            raise ValueError("message must be 1..4")
        if e.kind in {"key_installed", "key_deleted"}:
            completed = e.data.get("operation_completed")
            if e.source == "instrumentation" and completed is not True:
                raise ValueError("key state events require operation_completed=true and evidence of MAC effect")
            if e.source == "synthetic" and "operation_completed" in e.data and completed is not True:
                raise ValueError("synthetic key state cannot claim an incomplete operation")
        if e.kind == "key_installed":
            for name in ("key_id", "slot"):
                if not isinstance(e.data.get(name), str) or not e.data[name].strip():
                    raise ValueError(f"key_installed requires stable nonempty {name}")
        if e.kind == "msdu_delivered":
            if e.data.get("bss_type") != "infrastructure":
                raise ValueError("MSDU delivery checker supports infrastructure BSS only")
            if e.data.get("payload_class") not in {"eapol", "user_data"}:
                raise ValueError("MSDU delivery requires classified payload")
            if e.data.get("destination_path") not in {"peer_sta", "portal", "bridge", "local_upper", "pae"}:
                raise ValueError("MSDU delivery requires explicit destination path")
            if type(e.data.get("individually_addressed")) is not bool:
                raise ValueError("MSDU delivery requires individual/group addressing evidence")
            lineage = ("aggregate_id" in e.data, "subframe_index" in e.data)
            if any(lineage):
                if not all(lineage):
                    raise ValueError("Aggregate delivery requires both aggregate_id and subframe_index")
                if not isinstance(e.data["aggregate_id"], str) or not e.data["aggregate_id"].strip():
                    raise ValueError("Aggregate identity must be nonempty")
                index = e.data["subframe_index"]
                if type(index) is not int or not 0 <= index <= 65535:
                    raise ValueError("Subframe index must be a bounded zero-based integer")
        if e.kind == "wnm_response_sent":
            derived = {"decoded_oci", "oci_channel_comparison"}
            if derived.intersection(e.data):
                raise ValueError("WNM decoded OCI and comparison are internally derived fields")
        if e.kind == "wnm_response_sent" and "action_body_hex" in e.data:
            encoded = e.data["action_body_hex"]
            if not isinstance(encoded, str) or len(encoded) > 131070:
                raise ValueError("Expected bounded WNM plaintext body hex")
            decoded = decode_sleep_response(bytes.fromhex(encoded))
            fields = ("dialog_token", "action_type", "response_status", "key_data_length")
            for name in fields:
                if name in e.data and e.data[name] != decoded[name]:
                    raise ValueError("WNM decoded fields conflict with supplied metadata")
            # Local event copy: do not alter caller data or retain raw key bytes.
            data = {name: value for name, value in e.data.items() if name != "action_body_hex"}
            data.update({name: decoded[name] for name in fields})
            data["decoded_oci"] = decoded["oci"]
            if "link_channel" in data:
                reference = data.get("link_channel_evidence")
                if not isinstance(reference, str) or not reference.strip():
                    raise ValueError("Channel snapshot evidence reference required")
                data["oci_channel_comparison"] = compare_oci_channel(decoded["oci"], data["link_channel"])

            e = Event(e.kind, e.peer, e.session, e.source, e.evidence, data)
        if e.kind == "wnm_response_sent":
            for name, limit in (("dialog_token", 256), ("action_type", 256),
                                ("response_status", 256), ("key_data_length", 65536)):
                value = e.data.get(name)
                if type(value) is not int or not 0 <= value < limit:
                    raise ValueError(f"WNM response requires bounded integer {name}")
            token = e.data.get("request_dialog_token")
            if token is not None and (type(token) is not int or not 1 <= token <= 255):
                raise ValueError("Correlated WNM request token must be 1..255")
        self.sources.add(e.source)
        if e.source in {"pcap", "probe"}:
            self.observations.append({"event": e.kind, "peer": e.peer,
                "session": e.session, "evidence": e.evidence,
                "reason": "observed externally; AP internal acceptance unconfirmed"})
            if e.kind == "msdu_delivered":
                self.observations[-1]["reported_delivery"] = {
                    name: e.data[name] for name in ("bss_type", "payload_class",
                        "destination_path", "individually_addressed")}
                if "aggregate_id" in e.data:
                    self.observations[-1]["reported_delivery"].update({
                        name: e.data[name] for name in ("aggregate_id", "subframe_index")})
            return
        if e.kind in {"key_install_requested", "key_delete_requested"}:
            self.observations.append({"event": e.kind, "peer": e.peer,
                "session": e.session, "evidence": e.evidence,
                "slot": e.data["slot"],
                "reason": "key operation requested; MAC effect unconfirmed"})
            return
        if e.kind in {"group_update_started", "group_message1_sent", "group_message2_accepted"}:
            self._group_event(e)
            return
        if e.kind == "session_start":
            p = self.peers.get(e.peer)
            if (e.peer, e.session) in self.sessions:
                self.flag(e, "SESSION_ID_REUSE", "session identifiers must not be reused")
                return
            if p and (p.associated or p.authorized or p.keys or p.pending or p.timers):
                self.flag(e, "UNCLEAN_SESSION_REPLACEMENT", "previous context remains active")
                return
            self.peers[e.peer] = Peer(e.session)
            self.sessions.add((e.peer, e.session))
            self.history.append(dict(event=e.kind, peer=e.peer, session=e.session,
                                     before=None, after=self.peers[e.peer].snapshot(), evidence=e.evidence, source=e.source))
            return
        p = self.peers.get(e.peer)
        if p is None:
            self.flag(e, "NO_SESSION", "explicit session_start required")
            return
        if p.session != e.session:
            self.flag(e, "STALE_SESSION_EVENT", "event belongs to a different session")
            return
        before = p.snapshot()
        d = e.data
        if e.kind == "auth_accepted":
            allowed = {"psk"} if self.mode == Mode.WPA2 else {"sae"} if self.mode == Mode.WPA3 else {"psk", "sae"}
            akm = d.get("akm")
            if akm == "sae" and p.sae == "idle":
                self.abstractions.add("SAE commit/confirm not observed for at least one authentication")
            if akm not in allowed:
                self.flag(e, "AKM_POLICY", "AKM outside configured profile")
            else:
                if p.associated and p.akm != akm:
                    self.flag(e, "AKM_CONTEXT_CHANGE", "AKM changed in associated session")
                    return
                if akm == "sae" and p.sae not in {"idle", "accepted"}:
                    self.flag(e, "SAE_AUTH_BEFORE_CONFIRM", "detailed SAE exchange has not reached local acceptance")
                p.auth, p.akm = "accepted", akm
        elif e.kind == "assoc_accepted":
            if p.auth != "accepted":
                self.flag(e, "ASSOC_BEFORE_AUTH", "no confirmed authentication path")
            if p.akm == "sae" and d.get("pmf") is not True:
                self.flag(e, "SAE_WITHOUT_PMF", "SAE requires negotiated PMF")
            p.associated, p.pmf = True, d.get("pmf")
            if p.cleanup_required:
                self.flag(e, "REASSOC_BEFORE_CLEANUP", "old temporary context has not passed cleanup checkpoint")
        elif e.kind == "handshake_started":
            if not p.associated:
                self.flag(e, "HANDSHAKE_BEFORE_ASSOC", "no association")
            p.handshake = "running"
            p.exchange = d.get("exchange_id")
            if p.exchange is None:
                self.abstractions.add("M1-M4 not observed for at least one handshake")
            p.message, p.replay_counter = 0, None
            p.m3_counters.clear()
        elif e.kind == "rekey_started":
            # 重协商可以保留旧 PTK 供现有数据使用，但新的握手必须重新推进。
            if not p.associated or not p.authorized or "ptk" not in p.keys:
                self.flag(e, "REKEY_WITHOUT_CONTEXT", "rekey requires authorized association and current PTK")
            p.handshake, p.exchange = "running", d.get("exchange_id")
            if p.exchange is None:
                self.abstractions.add("M1-M4 not observed for at least one handshake")
            p.message, p.replay_counter = 0, None
            p.m3_counters.clear()
        elif e.kind == "handshake_completed":
            if p.handshake != "running":
                self.flag(e, "HANDSHAKE_SEQUENCE", "completion without running handshake")
            if p.exchange is not None and p.message != 4:
                self.flag(e, "INCOMPLETE_FOUR_WAY", "detailed exchange has not reached accepted M4")
            p.handshake = "complete"
        elif e.kind == "key_installed":
            key, slot = d.get("key_id"), d.get("slot")
            if not isinstance(key, str) or not key or not isinstance(slot, str) or not slot:
                raise ValueError("key_installed requires stable key_id and slot")
            if not p.associated:
                self.flag(e, "KEY_WITHOUT_ASSOC", "installation outside association")
            # Key IDs/slots select storage; they do not make reused material new.
            # The adapter must scope this model to one AP and provide stable IDs.
            installation = (e.peer, key)
            if installation in self.key_installations and d.get("counters_reset") is True:
                self.flag(e, "KEY_REINSTALL_RESET", "previously installed key material reinstalled with counter reset, including across slots, deletion or session replacement")
            self.key_installations.add(installation)
            p.keys[slot] = key
        elif e.kind == "key_deleted":
            p.keys.pop(d["slot"], None)
        elif e.kind == "port_authorized":
            if not p.associated or p.handshake != "complete" or "ptk" not in p.keys:
                self.flag(e, "EARLY_AUTHORIZATION", "missing association, completed handshake or installed PTK")
            p.authorized = True
        elif e.kind == "port_revoked":
            p.authorized = False
        elif e.kind == "work_pending":
            p.pending.add(d["work_id"])
        elif e.kind == "work_cleared":
            p.pending.discard(d["work_id"])
        elif e.kind in {"disassociated", "deauthenticated"}:
            # 断开只是观测到连接状态变化，绝不能替实现自动清理其他上下文。
            p.associated, p.handshake = False, "idle"
            p.wnm_sleep = None
            p.cleanup_required = True
            p.exchange, p.message, p.replay_counter = None, 0, None
            p.m3_counters.clear()
            if e.kind == "deauthenticated":
                p.auth = "none"
                p.akm, p.sae, p.sae_exchange = None, "idle", None
            # Do not assume deletion of keys, authorization or work.
        elif e.kind == "cleanup_checkpoint":
            if p.associated:
                self.flag(e, "INVALID_CHECKPOINT", "checkpoint requires disconnected peer")
            if p.authorized or p.keys or p.pending or p.timers:
                self.flag(e, "RESIDUAL_CONTEXT", "temporary context remains after configured cleanup deadline")
            elif not p.associated:
                p.cleanup_required = False
        elif e.kind == "encrypt_new":
            if not all(k in d for k in ("key_id", "nonce_domain", "nonce")):
                raise ValueError("encrypt_new requires key_id, nonce_domain and nonce")
            identity = (d["key_id"], d["nonce_domain"], d["nonce"])
            hash(identity)
            if not p.associated or not p.authorized:
                self.flag(e, "DATA_WITHOUT_AUTHORIZATION", "new user-data encryption outside authorized association")
            if d["key_id"] not in p.keys.values():
                self.flag(e, "UNINSTALLED_KEY_USE", "key absent from current context")
            if identity in self.nonces:
                self.flag(e, "NONCE_REUSE", "new encryption repeats nonce in same key/domain")
            self.nonces.add(identity)
        elif e.kind == "link_retry":
            pass  # 已有密文的链路重传不等于重新加密，不能直接判定 nonce 重用。
        elif self._extended(e, p):
            pass
        else:
            raise ValueError(f"unsupported event: {e.kind}")
        after = p.snapshot()
        self.coverage.add((before, e.kind, after))
        self.history.append({"event": e.kind, "peer": e.peer, "session": e.session,
                             "before": before, "after": after, "evidence": e.evidence, "source": e.source})

        if e.kind == "msdu_delivered":
            self.history[-1]["msdu_delivery"] = {
                name: d[name] for name in ("bss_type", "payload_class",
                    "destination_path", "individually_addressed")}
            if "aggregate_id" in d:
                self.history[-1]["msdu_delivery"].update({
                    name: d[name] for name in ("aggregate_id", "subframe_index")})

        if e.kind == "wnm_response_sent":
            self.history[-1]["wnm_response"] = {
                name: d[name] for name in ("dialog_token", "action_type",
                    "response_status", "key_data_length")}
            if "decoded_oci" in d:
                self.history[-1]["wnm_response"]["oci"] = d["decoded_oci"]
            if "oci_channel_comparison" in d:
                self.history[-1]["wnm_response"]["channel_comparison"] = d["oci_channel_comparison"]
                self.history[-1]["wnm_response"]["link_channel_evidence"] = d["link_channel_evidence"]


    def _extended(self, e, p):
        """细粒度事件必须来自实现插桩；收到无线帧不等于通过内部校验。"""
        d = e.data
        if e.kind == "sae_commit_accepted":
            if self.mode == Mode.WPA2 or p.associated:
                self.flag(e, "SAE_CONTEXT", "SAE commit outside allowed authentication context")
            else:
                p.sae, p.sae_exchange = "commit_accepted", d["exchange_id"]
        elif e.kind == "sae_confirm_accepted":
            if p.sae != "commit_accepted" or p.sae_exchange != d["exchange_id"]:
                self.flag(e, "SAE_CONFIRM_SEQUENCE", "confirm without matching accepted commit")
            else:
                # IEEE 802.11-2024 12.4.8.6.5: locally verified Confirm
                # reaches Accepted, not Confirmed. This event asserts internal
                # validation; it does not prove delivery of our Confirm to peer.
                p.sae, p.auth, p.akm = "accepted", "accepted", "sae"
                p.sae_exchange = None
        elif e.kind in {"auth_failed", "handshake_failed", "handshake_timeout"}:
            # 失败也不假定密钥已删；残留状态交给 cleanup_checkpoint 检查。
            p.handshake, p.cleanup_required = "failed", True
            if e.kind == "auth_failed":
                p.auth, p.sae, p.sae_exchange = "none", "failed", None
        elif e.kind == "handshake_message":
            n, counter = d["message"], d["replay_counter"]
            if not p.associated or p.handshake != "running" or p.exchange != d["exchange_id"]:
                self.flag(e, "HANDSHAKE_CONTEXT", "message outside matching running exchange")
            elif n == p.message and counter == p.replay_counter:
                pass  # Duplicate observation; installation is checked separately.
            elif n == p.message and n in (1, 3):
                # IEEE 802.11-2024 12.7.10.3: each Authenticator
                # EAPOL-Key transmission increments its replay counter.
                # Keep the phase while updating the response correlation value.
                if counter > p.replay_counter:
                    p.replay_counter = counter
                    if n == 3:
                        p.m3_counters.add(counter)
                else:
                    self.flag(e, "HANDSHAKE_REPLAY_COUNTER", "non-increasing authenticator retry counter")
            elif n == 4 and p.message == 3:
                # 12.7.6.5: M4 may match an earlier M3 transmission in
                # this exchange, but must exceed accepted session responses.
                if (counter not in p.m3_counters or
                        p.accepted_response_counter is not None and
                        counter <= p.accepted_response_counter):
                    self.flag(e, "HANDSHAKE_REPLAY_COUNTER", "M4 outside sent M3 history or not above accepted session response counter")
                else:
                    p.message, p.replay_counter = n, counter
                    p.accepted_response_counter = counter
            elif n != p.message + 1:
                self.flag(e, "HANDSHAKE_MESSAGE_ORDER", "unexpected four-way message order")
            elif p.replay_counter is not None and ((n in (2, 4) and counter != p.replay_counter) or (n == 3 and counter <= p.replay_counter)):
                self.flag(e, "HANDSHAKE_REPLAY_COUNTER", "response mismatch or non-increasing authenticator counter")
            else:
                p.message, p.replay_counter = n, counter
                if n == 3:
                    p.m3_counters.add(counter)
                elif n == 2:
                    p.accepted_response_counter = counter
        elif e.kind == "wnm_response_sent":
            # Semantic fields from an internally observed transmission only.
            # Do not infer remote acceptance or locally enabled sleep service.
            if not p.associated:
                self.flag(e, "WNM_WITHOUT_ASSOCIATION", "response outside association")
            action, status = d["action_type"], d["response_status"]
            if action not in (0, 1) or status > 5:
                self.flag(e, "WNM_RESERVED_VALUE", "reserved sleep action or response status")
            if status == 1 and action != 1:
                self.flag(e, "WNM_STATUS_ACTION", "update-required acceptance is an exit status")
            if d["dialog_token"] == 0 and (action != 1 or status != 1):
                self.flag(e, "WNM_UNSOLICITED_RESPONSE", "unsolicited exit requires exit/update-required status")
            request_token = d.get("request_dialog_token")
            if request_token is not None and d["dialog_token"] != request_token:
                self.flag(e, "WNM_DIALOG_MISMATCH", "response token differs from correlated request")
            if p.pmf is False and d["key_data_length"] != 0:
                self.flag(e, "WNM_KEY_DATA_WITHOUT_PMF", "key data sent without negotiated management protection")
        elif e.kind in {"wnm_sleep_enabled", "wnm_sleep_disabled"}:
            # Internal AP service state, not a request or an on-air response.
            if not p.associated:
                self.flag(e, "WNM_WITHOUT_ASSOCIATION", "WNM service state outside association")
            else:
                p.wnm_sleep = e.kind == "wnm_sleep_enabled"
        elif e.kind == "timer_started":
            p.timers.add(d["timer_id"])
        elif e.kind in {"timer_cancelled", "timer_expired"}:
            if e.kind == "timer_expired" and d["timer_id"] not in p.timers:
                self.flag(e, "UNKNOWN_TIMER", "expiry without active timer")
            p.timers.discard(d["timer_id"])
        elif e.kind == "management_accepted":
            if d.get("subtype") not in {"deauth", "disassoc"}:
                raise ValueError("management_accepted supports deauth/disassoc only")
            # PMF 已启用时，稳健管理帧须有保护与完整性校验证据。
            if p.associated and p.pmf and (d.get("protected") is not True or d.get("integrity_valid") is not True):
                self.flag(e, "UNPROTECTED_ROBUST_MGMT_ACCEPTED", "PMF management accepted without protection/integrity evidence")
        elif e.kind == "rx_counter_configured":
            # Trusted MAC configuration evidence, not an RSC merely seen on air.
            # Use the same full replay domain as subsequent data_accepted events.
            if d["key_id"] not in p.keys.values():
                self.flag(e, "RX_COUNTER_WITHOUT_KEY", "configured receive counter for absent key material")
            else:
                identity = (e.peer, d["key_id"], d["nonce_domain"])
                previous = self.rx_counters.get(identity, -1)
                if d["pn"] < previous:
                    self.flag(e, "RX_COUNTER_ROLLBACK", "configured replay floor below prior state for the same material/domain")
                self.rx_counters[identity] = max(previous, d["pn"])
        elif e.kind == "msdu_delivered":
            # Internal post-classification delivery evidence; not RF reception.
            if d["payload_class"] == "eapol":
                if d["destination_path"] != "pae":
                    self.flag(e, "EAPOL_FORWARDED", "received EAPOL delivered outside the local PAE")
                if not d["individually_addressed"]:
                    self.flag(e, "EAPOL_GROUP_ADDRESSED", "EAPOL delivered from a non-individually addressed MSDU")
            elif not p.associated or not p.authorized:
                self.flag(e, "MSDU_WITHOUT_AUTHORIZATION", "general data delivered outside authorized association")
        elif e.kind == "data_accepted":
            if not p.associated or not p.authorized:
                self.flag(e, "RX_WITHOUT_AUTHORIZATION", "user data accepted outside authorized association")
            if d["key_id"] not in p.keys.values():
                self.flag(e, "RX_UNINSTALLED_KEY", "accepted data uses absent key")
            identity = (e.peer, d["key_id"], d["nonce_domain"])
            # 跨 session 保留账本，防止复用同一密钥时重放计数器被悄悄清零。
            previous = self.rx_counters.get(identity, -1)
            if d["pn"] <= previous:
                self.flag(e, "RX_REPLAY_ACCEPTED", "accepted PN does not increase in supplied replay domain")
            self.rx_counters[identity] = max(previous, d["pn"])
        else:
            return False
        return True

    def _group_event(self, e):
        d = e.data
        identity = (d.get("bss_context"), d.get("update_id"))
        if not all(isinstance(x, str) and x.strip() for x in identity):
            raise ValueError("Group event requires BSS and update identities")
        if e.kind == "group_update_started":
            if identity in self.group_updates:
                self.flag(e, "GROUP_UPDATE_ID_REUSE", "group update identity already used")
                return
            ledger = GroupKeyDelivery(*identity, d.get("material_id"),
                                      d.get("members"), source=e.source)
            for peer, session in ledger.members.items():
                p = self.peers.get(peer)
                if p is None or p.session != session or not p.associated:
                    self.flag(e, "GROUP_MEMBER_CONTEXT", "snapshot member lacks matching association")
                elif p.wnm_sleep is True:
                    self.flag(e, "GROUP_SLEEPING_MEMBER", "WNM sleeping STA included in group update snapshot")
                elif p.handshake != "complete" or "ptk" not in p.keys:
                    self.flag(e, "GROUP_BEFORE_PAIRWISE_READY", "group update precedes completed pairwise context")
            self.group_updates[identity] = ledger
            return
        ledger = self.group_updates.get(identity)
        if ledger is None:
            self.flag(e, "GROUP_WITHOUT_UPDATE", "group message lacks explicit update snapshot")
            return
        if e.source != ledger.source:
            raise ValueError("Do not combine synthetic and instrumentation group state")
        p = self.peers.get(e.peer)
        if p is None or p.session != e.session or not p.associated:
            self.flag(e, "STALE_GROUP_MEMBER", "group message outside current association")
            return
        if p.wnm_sleep is True:
            self.flag(e, "GROUP_DURING_WNM_SLEEP", "group key exchange observed while WNM service enabled")
        before = len(ledger.findings)
        ledger.observe("message1_sent" if e.kind == "group_message1_sent" else "message2_accepted",
                       e.peer, e.session, d.get("replay_counter"),
                       context=identity[0], update_id=identity[1], evidence=e.evidence,
                       integrity_valid=d.get("integrity_valid", False))
        for finding in ledger.findings[before:]:
            self.flag(e, "GROUP_DELIVERY_CONTEXT", str(finding))

    def report(self):
        return {"mode": self.mode.value, "synthetic": self.sources == {"synthetic"},
            "status": "candidate_violation" if self.findings else "no_violation_observed",
            "conformance_proven": False,
            "limitations": "Offline abstraction; no conformance proof or real AP vulnerability claim. Unobserved properties are not proven. SAE stages summarize internal acceptance evidence, not the full SAE FSM; local acceptance does not prove peer completion.",
            "transition_count": len(self.coverage),
            "group_key_delivery": [ledger.report() for ledger in self.group_updates.values()],
            "stage_evidence": stage_evidence(self.history) if self.mode == Mode.WPA2 else None,
            "abstractions_used": sorted(self.abstractions),
            "state_fields": ["auth", "akm", "associated", "pmf", "wnm_sleep", "handshake", "authorized",
                             "keys", "pending", "sae", "sae_exchange", "exchange", "message", "replay_counter",
                             "cleanup_required", "timers", "m3_counters", "accepted_response_counter"],
            "findings": [asdict(f) for f in self.findings],
            "unconfirmed_observations": self.observations, "history": self.history}
