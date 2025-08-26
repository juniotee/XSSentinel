# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-
"""
Reporter utilities — terminal table only (no PDF/HTML).
All code/comments in English.
"""
from __future__ import annotations
from typing import Dict, List


def _short(s: str, n: int = 80) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[: n - 1] + "…"


def render_table(findings: List[Dict]) -> str:
    """
    Render a compact ASCII table for terminal.
    Columns: #, mode, target, exec, refl, sinks, url
    """
    rows = []
    header = ["#", "mode", "target", "exec", "refl", "sinks", "url"]
    rows.append(header)
    for i, f in enumerate(findings, 1):
        target = f.get("param") or f.get("field") or "-"
        sinks = f.get("sinks") or []
        rows.append([
            str(i),
            f.get("mode", "-"),
            _short(target, 20),
            "✓" if f.get("executed") else "",
            "✓" if f.get("reflected") else "",
            str(len(sinks)),
            _short(f.get("url", "-"), 80),
        ])
    # column widths
    w = [max(len(r[c]) for r in rows) for c in range(len(header))]
    lines = []
    for r in rows:
        line = "  ".join(r[c].ljust(w[c]) for c in range(len(header)))
        lines.append(line)
    return "\n".join(lines)
