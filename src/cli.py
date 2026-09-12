from __future__ import annotations

import argparse
from pathlib import Path

from .assessor import assess, load_events, render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic NTLM authentication telemetry")
    parser.add_argument("input", help="Path to synthetic authentication events JSON")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()

    events = load_events(args.input)
    findings = assess(events)
    report = render_markdown(findings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"generated {output} with {len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
