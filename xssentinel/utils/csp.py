
import re
from typing import Dict, List, Optional

def _parse_directive_list(val: str) -> List[str]:
    return [t.strip() for t in val.split() if t.strip()]

def parse_csp(header_value: Optional[str]) -> Dict:
    """
    Parse a CSP header string into a minimal feature set we care about.
    Returns keys:
      - raw: original header
      - script_src: list of tokens for script-src (or default-src fallback)
      - allows_inline: bool
      - allows_eval: bool
      - allows_data: bool
      - allows_blob: bool
    """
    info = {
        "raw": header_value or "",
        "script_src": [],
        "allows_inline": True,  # default CSP (absent) allows inline
        "allows_eval": True,
        "allows_data": True,
        "allows_blob": True,
    }
    if not header_value:
        return info
    # Split directives by semicolon
    directives = {}
    for d in header_value.split(";"):
        d = d.strip()
        if not d:
            continue
        if " " in d:
            name, val = d.split(" ", 1)
        else:
            name, val = d, ""
        directives[name.lower()] = val.strip()

    script_src = directives.get("script-src")
    if not script_src:
        script_src = directives.get("default-src")
    if script_src is not None:
        tokens = _parse_directive_list(script_src)
        info["script_src"] = tokens
        # Conservative defaults when script-src exists
        info["allows_inline"] = ("'unsafe-inline'" in tokens)
        info["allows_eval"] = ("'unsafe-eval'" in tokens)
        info["allows_data"] = ("data:" in tokens)
        info["allows_blob"] = ("blob:" in tokens)
    return info
