# xssentinel/crawler/browser_engine.py
# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-
"""
BrowserEngine: Playwright-based crawler/fuzzer with CSP capture, WAF tuning and evidence collection.

Features:
- Headless Chromium context with optional session HAR recording.
- Optional trace-on-hit (exports a Playwright trace ZIP per finding).
- User-Agent rotation (session/per-request).
- Pacing with jitter to smooth request bursts against WAF/CDN rate limits.
- Per-origin CSP capture (header + basic <meta http-equiv="content-security-policy">).
- Form fuzzing and URL parameter fuzzing with fragment (#) fallback for SPA routers.
- Sink capture (document.write, innerHTML, insertAdjacentHTML, setAttribute on*, location/history APIs).
- Evidence: screenshots, trace ZIP, session HAR.

All code and comments are in English by request.
"""
from __future__ import annotations

import asyncio
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, quote

from playwright.async_api import async_playwright, Page, Browser, BrowserContext, Response

# Internal helpers (provided by the rest of the project)
from ..detector.sandbox_executor import (
    wait_for_execution_signal,
    inject_init_script,
    get_sink_log,
)
from ..utils.csp import parse_csp


class BrowserEngine:
    def __init__(
        self,
        headless: bool = True,
        timeout_ms: int = 15000,
        evidence_dir: Path = Path("evidences"),
        user_agent: Optional[str] = None,
        pacing_ms: int = 0,
        jitter_pct: float = 0.0,
        ua_mode: Optional[str] = None,  # 'session' | 'per-request' | None
        trace_on_hit: bool = False,
        outdir: Optional[Path] = None,
        warmup_requests: int = 0,
        warmup_wait_ms: int = 500,
    ):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.evidence_dir = evidence_dir
        self.user_agent = user_agent
        self.pacing_ms = pacing_ms
        self.jitter_pct = jitter_pct
        self.ua_mode = ua_mode or "session"
        self.trace_on_hit = trace_on_hit
        self.outdir = outdir or Path(".")
        self.warmup_requests = warmup_requests
        self.warmup_wait_ms = warmup_wait_ms

        self._ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
        ]

        # Runtime state
        self._pw = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        self.last_csp: Optional[Dict[str, Any]] = None
        self.csp_by_origin: Dict[str, Dict[str, Any]] = {}

    # ---------------------------
    # Async context management
    # ---------------------------
    async def __aenter__(self) -> "BrowserEngine":
        self._pw = await async_playwright().start()
        self.browser = await self._pw.chromium.launch(headless=self.headless)

        # Global HAR for the session
        if self.user_agent:
            self.context = await self.browser.new_context(
                user_agent=self.user_agent,
                record_har_path=(self.outdir / "session.har").as_posix(),
            )
        else:
            self.context = await self.browser.new_context(
                record_har_path=(self.outdir / "session.har").as_posix()
            )

        if self.trace_on_hit:
            await self.context.tracing.start(screenshots=True, snapshots=True, sources=True)

        self.page = await self.context.new_page()
        self.page.set_default_timeout(self.timeout_ms)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            if self.context and self.trace_on_hit:
                # If tracing is still ongoing, stop without writing (avoid overwrite)
                try:
                    await self.context.tracing.stop()
                except Exception:
                    pass
        finally:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self._pw:
                await self._pw.stop()

    # ---------------------------
    # Helpers
    # ---------------------------
    async def _paced_sleep(self) -> None:
        """Sleep according to pacing_ms ± jitter_pct."""
        if not self.pacing_ms:
            return
        jitter = self.pacing_ms * self.jitter_pct
        delay = self.pacing_ms + (random.uniform(-jitter, jitter) if jitter else 0.0)
        if delay > 0:
            await asyncio.sleep(delay / 1000.0)

    async def _maybe_rotate_ua(self) -> None:
        """Rotate UA per request if ua_mode == 'per-request'."""
        if self.ua_mode == "per-request" and self.context:
            ua = random.choice(self._ua_pool)
            await self.context.set_extra_http_headers({"User-Agent": ua})

    async def _export_trace(self, tag: str) -> Optional[str]:
        """Export a Playwright trace when trace_on_hit is enabled, then restart tracing."""
        if not self.trace_on_hit or not self.context:
            return None
        trace_dir = self.outdir / "trace"
        trace_dir.mkdir(parents=True, exist_ok=True)
        path = trace_dir / f"trace_{tag}.zip"
        try:
            await self.context.tracing.stop(path=path.as_posix())
            # Restart tracing so subsequent steps continue capturing
            await self.context.tracing.start(screenshots=True, snapshots=True, sources=True)
            return path.as_posix()
        except Exception:
            return None

    async def warmup(self, url: str) -> None:
        """Perform a few gentle navigations to 'warm-up' WAF/CDN before fuzzing."""
        if self.warmup_requests <= 0 or not self.page:
            return
        for _ in range(self.warmup_requests):
            try:
                await self._maybe_rotate_ua()
                await self.page.goto(url, wait_until="domcontentloaded")
                await asyncio.sleep(max(0, self.warmup_wait_ms) / 1000.0)
            except Exception:
                # Warmup is best-effort
                pass

    async def set_cookies(self, cookies: List[Dict[str, Any]], url: str) -> None:
        """Load cookies into the context for the given URL's domain."""
        if not self.context:
            return
        await self.context.add_cookies(cookies)

    def get_csp_info(self) -> Optional[Dict[str, Any]]:
        """Return the last captured CSP as a dict with simple flags."""
        return self.last_csp

    # ---------------------------
    # CSP capture & navigation
    # ---------------------------
    async def _capture_csp_from_meta(self) -> Optional[str]:
        """
        Try to read <meta http-equiv="content-security-policy" content="..."> safely.
        Use a triple-quoted JS function string to avoid Python escaping issues.
        """
        assert self.page is not None
        try:
            content = await self.page.evaluate(
                """() => {
                    const m = document.querySelector('meta[http-equiv="content-security-policy"]');
                    return m ? m.getAttribute('content') : null;
                }"""
            )
            return content
        except Exception:
            return None

    async def navigate(self, url: str) -> Optional[Response]:
        """Navigate to a URL, capture CSP (header + meta), store per-origin CSP, and run warmup."""
        if not self.page:
            raise RuntimeError("Page not initialized")

        resp = await self.page.goto(url, wait_until="domcontentloaded")

        # Header CSP
        hdr = None
        try:
            if resp:
                headers = await resp.all_headers()
                hdr = headers.get("content-security-policy") or headers.get("Content-Security-Policy")
        except Exception:
            hdr = None

        # Meta CSP (safe triple-quoted JS)
        meta_csp = await self._capture_csp_from_meta()

        # Combine header/meta (prefer header; meta as fallback)
        raw_csp = hdr or meta_csp
        if raw_csp:
            self.last_csp = parse_csp(raw_csp)
        else:
            self.last_csp = None

        # Persist CSP by origin
        try:
            origin = await self.page.evaluate("() => location.origin")
            if origin:
                self.csp_by_origin[origin] = self.last_csp or {}
        except Exception:
            pass

        # Optional warmup loop
        await self.warmup(url)
        return resp

    # ---------------------------
    # Fuzzing primitives
    # ---------------------------
    async def _check_signals(self, marker: str) -> Tuple[bool, bool]:
        """
        Return (executed, reflected).
        executed: wait_for_execution_signal(marker) returns True within timeout.
        reflected: marker appears in DOM HTML snapshot.
        """
        executed = await wait_for_execution_signal(self.page, marker, timeout_ms=self.timeout_ms)
        try:
            html = await self.page.content()
            reflected = (marker in html)
        except Exception:
            reflected = False
        return executed, reflected

    async def _record_evidence(self, hit: Dict[str, Any], tag: str) -> None:
        """Screenshot + sinks + trace (when executed/reflected)."""
        assert self.page is not None

        # Screenshot
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        png = self.evidence_dir / f"hit_{tag}.png"
        try:
            await self.page.screenshot(path=png.as_posix(), full_page=True)
            hit["screenshot"] = png.as_posix()
        except Exception:
            pass

        # Sinks log
        try:
            hit["sinks"] = await get_sink_log(self.page)
        except Exception:
            hit["sinks"] = []

        # Trace ZIP
        if hit.get("executed") or hit.get("reflected"):
            hit["trace"] = await self._export_trace(tag)

    # ---------------------------
    # Form fuzzing
    # ---------------------------
    async def fuzz_forms(
        self,
        url: str,
        marker: str,
        payloads: List[str],
        max_forms: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Fill and submit named inputs in <form> elements.
        - Inject init script before each submission (ensures MutationObserver + hooks).
        - After submit, check execution/reflection, capture evidence.
        """
        results: List[Dict[str, Any]] = []
        await self.navigate(url)

        assert self.page is not None
        forms = await self.page.query_selector_all("form")
        for fidx, form in enumerate(forms[: max_forms if max_forms > 0 else len(forms)]):
            # Pick all named inputs inside this form
            inputs = await form.query_selector_all("input[name], textarea[name]")
            names = []
            for el in inputs:
                try:
                    nm = await el.get_attribute("name")
                    if nm:
                        names.append(nm)
                except Exception:
                    pass
            if not names:
                continue

            for name in names:
                for p in payloads:
                    try:
                        await self._maybe_rotate_ua()
                        # Ensure init script is injected for execution detection and sink hooks
                        await inject_init_script(self.page, marker)

                        # Fill every named field with benign data; target field with the payload
                        for el in inputs:
                            nm = await el.get_attribute("name")
                            if not nm:
                                continue
                            val = p if nm == name else f"test-{marker}"
                            try:
                                await el.fill(val)
                            except Exception:
                                pass

                        # Submit the form (try submit(); fallback to pressing Enter if needed)
                        try:
                            await form.evaluate("(f)=>f.submit()")
                        except Exception:
                            try:
                                await form.press("Enter")
                            except Exception:
                                pass

                        # Wait for DOMContentLoaded or network idle to stabilize page
                        try:
                            await self.page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
                        except Exception:
                            pass

                        executed, reflected = await self._check_signals(marker)

                        hit = {
                            "mode": "form",
                            "field": name,
                            "payload": p,
                            "executed": executed,
                            "reflected": reflected,
                            "url": self.page.url,
                            "csp": self.last_csp,
                        }

                        tag = f"form_{fidx}_{name}_{abs(hash(p)) % (10**8)}"
                        await self._record_evidence(hit, tag)
                        results.append(hit)

                        await self._paced_sleep()
                    except Exception as e:
                        results.append(
                            {
                                "mode": "form",
                                "field": name,
                                "payload": p,
                                "error": str(e),
                                "url": self.page.url if self.page else url,
                                "csp": self.last_csp,
                            }
                        )
        return results

    # ---------------------------
    # URL parameter fuzzing (+ fragment fallback)
    # ---------------------------
    async def fuzz_url_params(
        self,
        base_url: str,
        marker: str,
        payloads: List[str],
        max_params: int = 8,
        backoff_ms: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Fuzz URL parameters preserving existing query.
        If no hit, also try #fragment fallback and force a hashchange.
        """
        results: List[Dict[str, Any]] = []

        # Parse and preserve existing query
        parsed = urlparse(base_url)
        orig_params = parse_qsl(parsed.query, keep_blank_values=True)

        # Build a small param pool (existing + a few synthetic)
        param_candidates = [k for (k, _) in orig_params]
        synthetic = ["q", "query", "search", "id", "name", "title"]
        for s in synthetic:
            if s not in param_candidates:
                param_candidates.append(s)

        param_candidates = param_candidates[: max_params if max_params > 0 else len(param_candidates)]

        for pname in param_candidates:
            for p in payloads:
                try:
                    await self._maybe_rotate_ua()
                    # Build query preserving existing keys/values, replacing/adding pname
                    qdict = dict(orig_params)
                    qdict[pname] = p
                    new_query = urlencode(qdict, doseq=True)

                    new_url = urlunparse(parsed._replace(query=new_query))
                    await inject_init_script(self.page, marker)  # ensure hooks for each nav
                    await self.page.goto(new_url, wait_until="domcontentloaded")

                    executed, reflected = await self._check_signals(marker)
                    status = None
                    try:
                        resp = await self.page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
                        # Playwright doesn't expose status here; leave None
                    except Exception:
                        pass

                    hit = {
                        "mode": "url_param",
                        "param": pname,
                        "payload": p,
                        "executed": executed,
                        "reflected": reflected,
                        "status": status,
                        "url": self.page.url,
                        "csp": self.last_csp,
                    }
                    tag = f"param_{pname}_{abs(hash(p)) % (10**8)}"
                    await self._record_evidence(hit, tag)
                    results.append(hit)

                    # Fragment fallback (for SPAs) if not executed/reflected
                    if not executed and not reflected:
                        frag_val = quote(p, safe="")
                        frag_url = new_url.split("#", 1)[0] + f"#{frag_val}"
                        await inject_init_script(self.page, marker)
                        await self.page.goto(frag_url, wait_until="domcontentloaded")
                        # nudge routers that listen to hashchange
                        try:
                            await self.page.evaluate("() => window.dispatchEvent(new HashChangeEvent('hashchange'))")
                        except Exception:
                            pass

                        executed2, reflected2 = await self._check_signals(marker)
                        hit2 = {
                            "mode": "url_fragment",
                            "param": pname,
                            "payload": p,
                            "executed": executed2,
                            "reflected": reflected2,
                            "url": self.page.url,
                            "csp": self.last_csp,
                        }
                        tag2 = f"fragment_{pname}_{abs(hash(p)) % (10**8)}"
                        await self._record_evidence(hit2, tag2)
                        results.append(hit2)

                    # pacing + potential UA rotation between iterations
                    await self._paced_sleep()
                except Exception as e:
                    results.append(
                        {
                            "mode": "url_param",
                            "param": pname,
                            "payload": p,
                            "error": str(e),
                            "url": self.page.url if self.page else base_url,
                            "csp": self.last_csp,
                        }
                    )
                    # crude backoff on repeated errors
                    await asyncio.sleep(max(0, backoff_ms) / 1000.0)

        return results
