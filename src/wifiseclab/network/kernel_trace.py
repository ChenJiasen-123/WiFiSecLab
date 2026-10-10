"""Private tracefs instance and metadata-only mac80211 debugfs snapshots."""
from pathlib import Path
import os

class KernelTrace:
    def __init__(self, output, token):
        self.output = Path(output)
        self.path = Path("/sys/kernel/tracing/instances") / token
        self.active = False
    def start(self):
        self.path.mkdir()  # Never reuse or modify another tracing instance.
        try:
            (self.path / "buffer_size_kb").write_text("4096")
            (self.path / "events/cfg80211/enable").write_text("1")
            for name in ("drv_set_key", "drv_return_int"):
                (self.path / f"events/mac80211/{name}/enable").write_text("1")
            (self.path / "tracing_on").write_text("1")
            self.active = True
        except BaseException:
            self.stop()
            raise
    def checkpoint(self, phase, phy):
        if self.active:
            (self.path / "trace_marker").write_text(phase)
            (self.output / (phase + "-kernel-trace.txt")).write_text((self.path / "trace").read_text())
        base = Path("/sys/kernel/debug/ieee80211") / phy
        result = {"phy": phy, "phase": phase, "available": base.exists(), "directories": []}
        if base.exists():
            for directory, dirs, files in os.walk(base, followlinks=False):
                relative = str(Path(directory).relative_to(base))
                result["directories"].append(relative)
                if relative.count("/") > 4:
                    dirs[:] = []
        import json
        (self.output / (phase + "-debugfs.json")).write_text(json.dumps(result, indent=2))
    def stop(self):
        if self.path.exists():
            try:
                (self.path / "tracing_on").write_text("0")
                (self.output / "kernel-trace.txt").write_text((self.path / "trace").read_text())
                stats = {}
                for path in self.path.glob("per_cpu/cpu*/stats"):
                    stats[path.parent.name] = path.read_text()
                import json
                (self.output / "trace-stats.json").write_text(json.dumps(stats, indent=2))
                (self.path / "events/enable").write_text("0")
            finally:
                self.path.rmdir()
                self.active = False
