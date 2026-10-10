"""Physical-radio role binding. Discovery only: does not change modes or transmit."""
from dataclasses import asdict, dataclass
from pathlib import Path
import re
import subprocess


@dataclass(frozen=True)
class Radio:
    interface: str
    phy: str
    usb_id: str
    driver: str
    monitor_supported: bool
    frequencies: frozenset[int]


# Bind by hardware identity rather than unstable wlan/phy enumeration.
ROLE_HARDWARE = {
    "injector": ("0cf3:9271", "ath9k_htc"),
    "listener": ("0e8d:7612", "mt76x2u"),
}


def discover(root=Path("/sys/class/net"), run=subprocess.check_output):
    radios = []
    for interface in sorted(root.iterdir()):
        if not (interface / "phy80211").exists():
            continue
        device = (interface / "device").resolve()
        usb = next((p for p in (device, *device.parents)
                    if (p / "idVendor").exists() and (p / "idProduct").exists()), None)
        if usb is None:
            continue
        usb_id = ":".join((usb / name).read_text().strip().lower()
                          for name in ("idVendor", "idProduct"))
        phy = (interface / "phy80211").resolve().name
        info = run(["iw", "phy", phy, "info"], text=True)
        frequencies = frozenset(int(m.group(1)) for m in re.finditer(
            r"\*\s+(\d+)(?:\.\d+)? MHz[^\n]*", info)
            if "disabled" not in m.group(0))
        radios.append(Radio(interface.name, phy, usb_id,
                            (device / "driver").resolve().name,
                            bool(re.search(r"^\s*\* monitor\s*$", info, re.M)),
                            frequencies))
    return radios


@dataclass(frozen=True)
class RadioRoles:
    injector: Radio
    listener: Radio
    channel: int

    @classmethod
    def bind(cls, radios, channel=1):
        # AR9271 limits this two-radio arrangement to 2.4 GHz channels 1..11.
        if type(channel) is not int or not 1 <= channel <= 11:
            raise ValueError("AR9271 + MT7612U require a common 2.4 GHz channel (1..11)")
        selected = {}
        for role, (usb_id, driver) in ROLE_HARDWARE.items():
            matches = [r for r in radios if r.usb_id == usb_id and r.driver == driver]
            if len(matches) != 1:
                raise ValueError(f"{role}: expected exactly one {usb_id}/{driver}, found {len(matches)}")
            radio = matches[0]
            if not radio.monitor_supported:
                raise ValueError(f"{role}: monitor mode unavailable on {radio.interface}")
            if 2407 + channel * 5 not in radio.frequencies:
                raise ValueError(f"{role}: channel {channel} unavailable on {radio.interface}")
            selected[role] = radio
        if (selected["injector"].phy == selected["listener"].phy or
                selected["injector"].interface == selected["listener"].interface):
            raise ValueError("Injection and listening require two independent radios")
        return cls(**selected, channel=channel)

    def interface_for(self, role):
        if role not in ROLE_HARDWARE:
            raise ValueError(f"Unknown radio role: {role}")
        return getattr(self, role).interface

    def report(self):
        result = {role: {**asdict(getattr(self, role)),
                         "frequencies": sorted(getattr(self, role).frequencies)}
                  for role in ROLE_HARDWARE}
        return {"channel": self.channel, "roles": result,
                "injection_verified": False,
                "note": "Hardware role plan only; injection requires a separate over-air validation."}
