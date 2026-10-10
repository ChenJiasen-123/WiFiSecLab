import argparse
import json
from pathlib import Path
from wifiseclab.core.model import APModel, Event, Mode

def main():
    parser = argparse.ArgumentParser(description="Offline AP state trace checker")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--mode", choices=[m.value for m in Mode], required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    model = APModel(Mode(args.mode))
    try:
        # 兼容 Windows 编辑器写出的 UTF-8 BOM，同时支持普通 UTF-8。
        raw = json.loads(args.trace.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, list) or not raw:
            raise ValueError("trace must be a nonempty array")
        for number, value in enumerate(raw, 1):
            try:
                model.apply(Event.parse(value))
            except (TypeError, ValueError, KeyError) as exc:
                raise ValueError(f"event {number}: {exc}") from exc
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    result = json.dumps(model.report(), ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result + "\n", encoding="utf-8")
    print(result)
    return 1 if model.findings else 0

if __name__ == "__main__":
    raise SystemExit(main())
