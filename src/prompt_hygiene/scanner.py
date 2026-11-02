"""Conservative, explainable text pattern detection without network calls."""

from __future__ import annotations

import re
from typing import Any


RULES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("email", "medium", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "email address"),
    ("phone", "medium", re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{7,}\d)(?!\w)"), "phone-like number"),
    ("api_key", "high", re.compile(r"\b(?:sk|pk|api)[_-][A-Za-z0-9_-]{16,}\b", re.I), "API-key-like token"),
    ("private_key", "high", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key header"),
    ("password_assignment", "high", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]+", re.I), "password assignment"),
)


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}…{value[-3:]}"


def scan(text: str) -> dict[str, Any]:
    """Return detected patterns with offsets and redacted evidence.

    This uses heuristics. It must support review, not certify that text is safe
    or that all sensitive data was found.
    """
    findings: list[dict[str, Any]] = []
    for category, severity, pattern, description in RULES:
        for match in pattern.finditer(text):
            findings.append({
                "category": category,
                "severity": severity,
                "description": description,
                "start": match.start(),
                "end": match.end(),
                "evidence": _redact(match.group()),
            })
    findings.sort(key=lambda item: (item["start"], item["category"]))
    return {
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": sum(item["severity"] == "high" for item in findings),
            "review_recommended": bool(findings),
        },
        "limitations": "Heuristic local checks only; review the original text and applicable policy before sharing.",
    }
