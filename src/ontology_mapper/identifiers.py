"""Identifier normalization helpers for stable SEPSES resource IRIs."""

from __future__ import annotations

import re
from urllib.parse import quote


def clean_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return re.sub(r"\s+", " ", text)


def slugify(value: object | None, *, lowercase: bool = True) -> str:
    text = clean_text(value) or "unknown"
    if lowercase:
        text = text.lower()
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-zA-Z0-9_.-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-._")
    return quote(text or "unknown", safe="-_.:")


def normalize_capec_id(value: object | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    if text.upper().startswith("CAPEC-"):
        return text.upper()
    return f"CAPEC-{text}"


def normalize_cwe_id(value: object | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    text = text.upper().replace("CWE-", "")
    return f"CWE-{text}"


def normalize_cve_id(value: object | None) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    return text.upper()


def split_multi_value(value: object | None, separators: str = r"[;,|]") -> list[str]:
    text = clean_text(value)
    if not text:
        return []
    parts = [p.strip() for p in re.split(separators, text) if p and p.strip()]
    return parts
