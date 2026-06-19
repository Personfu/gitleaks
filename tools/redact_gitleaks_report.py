#!/usr/bin/env python3
"""Summarize a Gitleaks JSON report without exposing secret material."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def load_report(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    return raw.get("findings", [])


def render(findings: list[dict[str, Any]]) -> str:
    rules = Counter(str(item.get("RuleID", item.get("rule", "unknown"))) for item in findings)
    lines = ["# Redacted Secret Scan Summary", "", f"Findings: {len(findings)}", "", "## Rule Counts", ""]
    for rule, count in rules.most_common():
        lines.append(f"- `{rule}`: {count}")

    lines.extend(["", "## Evidence Index", ""])
    for item in findings:
        secret = str(item.get("Secret", item.get("secret", "")))
        file_name = str(item.get("File", item.get("file", "unknown")))
        line = str(item.get("StartLine", item.get("line", "?")))
        rule = str(item.get("RuleID", item.get("rule", "unknown")))
        lines.append(f"- `{rule}` in `{file_name}:{line}` — fingerprint `{fp(secret) if secret else 'none'}`")

    lines.extend([
        "",
        "## Handling Standard",
        "Do not paste raw secrets into tickets, chat, screenshots, or customer reports. Rotate affected credentials, verify blast radius, and attach only the redacted evidence index above.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create redacted Markdown from a Gitleaks JSON report.")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(render(load_report(args.input)), encoding="utf-8")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
