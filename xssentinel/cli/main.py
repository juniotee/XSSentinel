# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-
"""
XSSentinel CLI — terminal-first output (table/json/ndjson/summary), no PDF.
Supports external wordlists via --wordlist (extend/replace).
All code/comments in English.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import string
from pathlib import Path
from typing import Dict, List, Optional

from ..crawler.browser_engine import BrowserEngine
from ..payloads.mutator import build_payloads
from ..reports.reporter import render_table


def _rand_marker(n: int = 6) -> str:
    return "".join(random.choice(string.hexdigits.lower()) for _ in range(n))


def _print_stdout(findings: List[Dict], mode: str = "table") -> None:
    if mode == "json":
        print(json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    elif mode == "ndjson":
        for f in findings:
            print(json.dumps(f, ensure_ascii=False))
    elif mode == "summary":
        total = len(findings)
        execs = sum(1 for f in findings if f.get("executed"))
        refls = sum(1 for f in findings if f.get("reflected"))
        print(f"Total: {total}  |  Executed: {execs}  |  Reflected: {refls}")
    else:  # table (default)
        print(render_table(findings))


async def run(args: argparse.Namespace) -> int:
    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    marker = args.marker or _rand_marker(6)
    print(f"Target: {args.url}    marker={marker}")

    async with BrowserEngine(
        headless=args.headless,
        timeout_ms=args.timeout_ms,
        evidence_dir=outdir / "evidences",
        user_agent=args.user_agent,
        pacing_ms=args.pacing_ms,
        jitter_pct=args.jitter_pct,
        ua_mode=args.ua_rotate,
        trace_on_hit=args.trace_on_hit,
        outdir=outdir,
        warmup_requests=args.warmup_requests,
        warmup_wait_ms=args.warmup_wait_ms,
    ) as eng:

        # Build payloads (CSP-aware + external wordlists)
        # First navigate once to capture CSP if requested
        if args.csp_aware:
            await eng.navigate(args.url)

        payloads = await build_payloads(
            csp=eng.get_csp_info() if args.csp_aware else None,
            marker=marker,
            sink_hints=[],  # can be filled after first pass if you loop
            external_paths=args.wordlist or [],
            mode=args.wordlist_mode,
            max_payloads=args.max_payloads,
            seed=args.seed,
        )

        findings: List[Dict] = []

        # URL param fuzzing (preserve query + fragment fallback)
        if args.fuzz_url:
            fz = await eng.fuzz_url_params(
                base_url=args.url,
                marker=marker,
                payloads=payloads,
                max_params=args.max_params,
                backoff_ms=args.backoff_ms,
            )
            findings.extend(fz)

        # Form fuzzing
        if args.fuzz_forms:
            ff = await eng.fuzz_forms(
                url=args.url,
                marker=marker,
                payloads=payloads,
                max_forms=args.max_forms,
            )
            findings.extend(ff)

        # Always write a JSON (artefato útil em CI), mas nada de PDF/HTML aqui
        (outdir / "report.json").write_text(
            json.dumps({"findings": findings}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # Print to terminal
        _print_stdout(findings, args.stdout)

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="XSSentinel — Playwright-powered XSS scanner (terminal-first).")

    # Target
    p.add_argument("--url", required=True, help="Target URL (authorized scope).")
    p.add_argument("--headless", action="store_true", default=True, help="Run headless (default).")
    p.add_argument("--timeout-ms", type=int, default=15000)
    p.add_argument("--out", default="./results", help="Output directory for evidences/trace/HAR/report.json")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--marker", default=None, help="Custom marker value to detect reflections/exec.")

    # CSP-aware
    p.add_argument("--csp-aware", action="store_true", help="Capture CSP and adapt payload selection.")

    # Fuzzing
    p.add_argument("--fuzz-url", action="store_true", help="Fuzz URL parameters (preserve query + fragment fallback).")
    p.add_argument("--max-params", type=int, default=8)
    p.add_argument("--backoff-ms", type=int, default=500)

    p.add_argument("--fuzz-forms", action="store_true", help="Fuzz HTML forms (named inputs).")
    p.add_argument("--max-forms", type=int, default=10)

    # WAF tuning
    p.add_argument("--user-agent", default=None)
    p.add_argument("--ua-rotate", default="session", choices=["session", "per-request"])
    p.add_argument("--warmup-requests", type=int, default=0)
    p.add_argument("--warmup-wait-ms", type=int, default=800)
    p.add_argument("--pacing-ms", type=int, default=0)
    p.add_argument("--jitter-pct", type=float, default=0.0)

    # Evidence
    p.add_argument("--trace-on-hit", action="store_true", help="Export a Playwright trace ZIP per hit.")

    # Wordlists externas
    p.add_argument("--wordlist", action="append", help="External wordlist file (can be repeated).")
    p.add_argument("--wordlist-mode", choices=["extend", "replace"], default="extend",
                   help="How to use external payloads: extend built-ins (default) or replace them.")

    # Terminal output
    p.add_argument("--stdout", choices=["table", "json", "ndjson", "summary"], default="table",
                   help="How to print results to the terminal.")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    # Ensure deterministic transforms if seed given
    random.seed(args.seed)
    exit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
