"""Conservative cfg80211 key operation/return correlation."""
import re

LINE = re.compile(r"^\s*(?P<task>.+)-(?P<pid>\d+)\s+\[\d+\]\s+\S+\s+(?P<time>[0-9.]+):\s+(?P<event>\w+):\s*(?P<body>.*)$")

def parse_trace(text):
    pending, operations, markers = {}, [], {}
    for number, line in enumerate(text.splitlines(), 1):
        match = LINE.match(line)
        if not match:
            continue
        d = match.groupdict(); pid = d["pid"]; event = d["event"]; body = d["body"]
        if event == "tracing_mark_write":
            marker = body.strip()
            # A repeated phase cannot identify one unambiguous interval.
            markers[marker] = number if marker not in markers else None
        elif event.startswith("rdev_return"):
            op = pending.pop(pid, None)
            if op and event == "rdev_return_int":
                ret = re.match(r"(phy\d+), returned: (-?\d+)$", body)
                if ret and ret.group(1) == op["phy"]:
                    op["return_code"] = int(ret.group(2))
                    op["return_line"] = number
        elif event.startswith("rdev_"):
            # 同一线程出现其他 cfg80211 入口时放弃旧配对，避免错接返回值。
            pending.pop(pid, None)
            if event in {"rdev_add_key", "rdev_del_key"}:
                parsed = re.match(r"(phy\d+),.*key_index: (\d+),.*pairwise: (true|false), mac addr: ([0-9a-f:]+)", body)
                if parsed:
                    op = dict(operation=event, phy=parsed[1], slot=int(parsed[2]),
                        pairwise=parsed[3] == "true", peer=parsed[4], pid=int(pid),
                        time=float(d["time"]), request_line=number, return_code=None,
                        return_line=None)
                    operations.append(op)
                    pending[pid] = op
    return operations, markers

def analyze(text, phy, peer, stats=None):
    operations, markers = parse_trace(text)
    selected = [o for o in operations if o["phy"] == phy and o["peer"] == peer and o["pairwise"]]
    def success(op, low, high):
        # 请求与返回都必须在阶段边界内；仅有删除请求不能证明删除成功。
        return [o for o in selected if o["operation"] == op and o["return_code"] == 0
                and low < o["request_line"] and o["return_line"] < high]
    connected, disconnected, reconnected = [markers.get(x) for x in ("connect", "disconnect", "reconnect")]
    checks = {"first_pairwise_add_accepted": "unknown", "disconnect_pairwise_delete_accepted": "unknown", "reconnect_pairwise_add_accepted": "unknown"}
    phase_valid = (all(x is not None for x in (connected, disconnected, reconnected))
                   and connected < disconnected < reconnected)
    if phase_valid:
        for name, op, low, high in [
            ("first_pairwise_add_accepted", "rdev_add_key", 0, connected),
            ("disconnect_pairwise_delete_accepted", "rdev_del_key", connected, disconnected),
            ("reconnect_pairwise_add_accepted", "rdev_add_key", disconnected, reconnected)]:
            checks[name] = "observed" if success(op, low, high) else "not_confirmed"
    if not phase_valid:
        checks = {name: "unknown_phase_boundaries" for name in checks}
    dropped = False
    if not stats:
        checks = {name: "unknown_trace_loss" for name in checks}
    else:
        for value in stats.values():
            for field in ("overrun", "commit overrun", "dropped events"):
                m = re.search(r"^" + field + r":\s*(\d+)", value, re.MULTILINE)
                if not m or int(m[1]) != 0:
                    dropped = True
        if dropped:
            checks = {name: "unknown_trace_loss" for name in checks}
    return dict(phy=phy, peer=peer, checks=checks, operations=selected,
        trace_loss_detected=dropped,
        phase_boundaries_valid=phase_valid,
        phase_markers=markers,
        evidence_level="cfg80211_call_return",
        evidence_scope="selected_peer_pairwise_key_operations_only",
        group_integrity_key_configuration_confirmed=False,
        integrity_key_replay_floor_confirmed=False,
        operation_completed=False,
        ap_state_conformance_confirmed=False,
        interpretation="return 0 confirms cfg80211 operation acceptance, not memory erasure or physical firmware state",
        not_verified=["key material identity/freshness", "memory erasure", "physical firmware key state", "queue/timer cleanup", "old-session input rejection"])
