from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan local text for likely sensitive content before AI sharing.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--file", type=Path)
    parser.add_argument("--output", type=Path, default=Path("prompt_hygiene_report.json"))
    args = parser.parse_args()
    text = args.text if args.text is not None else args.file.read_text(encoding="utf-8")
    report = scan(text)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"]))
    if report["summary"]["high"]:
        sys.exit(2)
