import asyncio
from typing import Dict, Any, List, Tuple
from pathlib import Path
from playwright.async_api import async_playwright, Browser, Page, BrowserContext
from ..detector.sandbox_executor import wait_for_execution_signal, inject_init_script, get_sink_log
from ..utils.csp import parse_csp
import urllib.parse

class BrowserEngine:
    def __init__(self, headless: bool = True, timeout_ms: int = 15000, evidence_dir: Path = Path('evidences'), user_agent: str | None = None, pacing_ms: int = 0, jitter_pct: float = 0.0, ua_mode: str | None = None, trace_on_hit: bool = False, outdir: Path | None = None, warmup_requests: int = 0, warmup_wait_ms: int = 500):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.evidence_dir = evidence_dir
        self.browser: Browser = None
        self.user_agent = user_agent
        self.pacing_ms = pacing_ms
        self.jitter_pct = jitter_pct
        self.ua_mode = ua_mode or 'session'
        self.trace_on_hit = trace_on_hit
        self.outdir = outdir or Path('.')
        self.warmup_requests = warmup_requests
        self.warmup_wait_ms = warmup_wait_ms
        self._ua_pool = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1'
        ]
        self.context: BrowserContext = None
        self.page: Page = None
        self.last_csp = None

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        # Create context with HAR recording for the whole session
        self.context = await self.browser.new_context(user_agent=self.user_agent, record_har_path=(self.outdir / 'session.har').as_posix()) if self.user_agent else await self.browser.new_context(record_har_path=(self.outdir / 'session.har').as_posix())
        if self.trace_on_hit:
            await self.context.tracing.start(screenshots=True, snapshots=True, sources=True)
        self.page = await self.context.new_page()
        self.page.set_default_timeout(self.timeout_ms)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()

    async def set_cookies(self, cookies: List[Dict[str, Any]], base_url: str):
        await self.context.add_cookies(cookies)

    async def navigate(self, url: str):
        resp = await self.page.goto(url)
        await self.warmup(url)
        try:
            hdr = resp.headers.get('content-security-policy') if resp else None
        except Exception:
            hdr = None
        if not hdr:
            try:
                hdr = await self.page.evaluate("() => { const m=document.querySelector('meta[http-equiv=\\"content-security-policy\\"]'); return m? m.getAttribute('content') : null }")
            except Exception:
                hdr = None
        self.last_csp = parse_csp(hdr)

    async def discover_forms(self, max_forms: int = 10) -> List[Dict[str, Any]]:
        # Retorna metadados de formulários e campos
        js = """
        () => {
            const forms = Array.from(document.querySelectorAll('form'));
            return forms.slice(0, %d).map((f, idx) => {
                const inputs = Array.from(f.querySelectorAll('input[name], textarea[name]'))
                    .map(el => ({name: el.getAttribute('name'), type: el.getAttribute('type')||'text'}));
                const buttons = Array.from(f.querySelectorAll('button, input[type=submit]'))
                    .map(el => ({text: el.innerText||el.value||'', type: el.tagName.toLowerCase()}));
                return {index: idx, inputs, hasSubmit: buttons.length>0};
            });
        }
        """ % max_forms
        return await self.page.evaluate(js)

    async def submit_form_with_payload(self, form_index: int, field_name: str, payload: str) -> Tuple[bool, str]:
        # Preenche um campo específico e submete o form
        js_fill = f"""
        (payload) => {{
            const forms = Array.from(document.querySelectorAll('form'));
            const f = forms[{form_index}];
            if (!f) return false;
            const el = f.querySelector('[name="{field_name}"]');
            if (!el) return false;
            el.focus();
            el.value = payload;
            try {{ el.dispatchEvent(new Event('input', {{bubbles:true}})); }} catch(e) {{}}
            try {{ el.dispatchEvent(new Event('change', {{bubbles:true}})); }} catch(e) {{}}
            const btn = f.querySelector('button, input[type=submit]');
            if (btn) btn.click();
            else f.submit();
            return true;
        }}
        """
        ok = await self.page.evaluate(js_fill, payload)
        await self.page.wait_for_load_state('networkidle')
        html = await self.page.content()
        return ok, html

    async def fuzz_forms(self, url: str, marker: str, payloads: List[str], max_forms: int = 10) -> List[Dict[str, Any]]:
        results = []
        await inject_init_script(self.page, marker)
        await self.navigate(url)
        forms = await self.discover_forms(max_forms=max_forms)
        for f in forms:
            for inp in f['inputs']:
                fname = inp['name']
                for p in payloads:
                    try:
                        ok, html = await self.submit_form_with_payload(f['index'], fname, p)
                        executed = await wait_for_execution_signal(self.page, marker, timeout_ms=3000)
                        hit = {
                            'form_index': f['index'],
                            'field': fname,
                            'payload': p,
                            'executed': executed,
                            'reflected': (marker in html),
                            'url': self.page.url,
                        }
                        if executed or hit['reflected']:
                            # screenshot evidence
                            self.evidence_dir.mkdir(parents=True, exist_ok=True)
                            path = self.evidence_dir / f"hit_{fname}_{abs(hash(p)) % (10**8)}.png"
                            await self.page.screenshot(path=path.as_posix(), full_page=True)
                            hit['screenshot'] = path.as_posix()
                        try:
                            hit['sinks'] = await get_sink_log(self.page)
                        except Exception:
                            hit['sinks'] = []
                        if (executed or hit['reflected']):
                            tag = f"form_{f['index']}_{fname}_{abs(hash(p)) % (10**8)}"
                            hit['trace'] = await self._export_trace(tag)
                        results.append(hit)
                        await self._paced_sleep()
                        await self._maybe_rotate_ua()
                    except Exception as e:
                        results.append({
                            'form_index': f['index'], 'field': fname, 'payload': p,
                            'error': str(e), 'url': self.page.url
                        })
        return results

    def get_csp_info(self):
        return self.last_csp or parse_csp(None)

    async def fuzz_url_params(self, url: str, marker: str, payloads, max_params: int = 10, backoff_ms: int = 500) -> list[dict]:
        # Includes fragment fallback (#) for DOM-based sinks
        results = []
        await inject_init_script(self.page, marker)
        parsed = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        candidates = list(q.keys()) if q else ['q','s','search','query','id','name','page','return','next','redirect','cb','callback']
        candidates = candidates[:max_params] if max_params else candidates
        current_backoff = backoff_ms
        for pname in candidates:
            for p in payloads:
                try:
                    newq = dict(q)
                    newq[pname] = [p]
                    new_query = urllib.parse.urlencode(newq, doseq=True, safe=':/#?&=,+%')
                    new_url = parsed._replace(query=new_query).geturl()
                    resp = await self.page.goto(new_url, wait_until='networkidle')
                    status = None
                    try:
                        status = resp.status if resp else None
                    except Exception:
                        status = None
                    if status in (403, 429):
                        await asyncio.sleep(current_backoff/1000)
                        current_backoff = min(current_backoff*2, 8000)
                        resp = await self.page.goto(new_url, wait_until='networkidle')
                        try:
                            status = resp.status if resp else None
                        except Exception:
                            status = None
                    else:
                        current_backoff = backoff_ms
                    html = await self.page.content()
                    executed = await wait_for_execution_signal(self.page, marker, timeout_ms=3000)
                    hit = {
                        'mode': 'url_param',
                        # default: query injection attempt completed

                        'param': pname,
                        'payload': p,
                        'executed': executed,
                        'reflected': (marker in html),
                        'status': status,
                        'url': self.page.url,
                    }
                    if executed or hit['reflected']:
                        self.evidence_dir.mkdir(parents=True, exist_ok=True)
                        path = self.evidence_dir / f"hit_param_{pname}_{abs(hash(p)) % (10**8)}.png"
                        await self.page.screenshot(path=path.as_posix(), full_page=True)
                        hit['screenshot'] = path.as_posix()
                    results.append(hit)
                    if self.pacing_ms:
                        await asyncio.sleep(self.pacing_ms/1000)

                except Exception as e:
                    results.append({'mode':'url_param','param':pname,'payload':p,'error':str(e),'url': self.page.url})
        return results


    async def _paced_sleep(self):
        if not self.pacing_ms:
            return
        import random, asyncio as _asyncio
        jitter = self.pacing_ms * self.jitter_pct
        delay = self.pacing_ms + (random.uniform(-jitter, jitter) if jitter else 0)
        if delay > 0:
            await _asyncio.sleep(delay/1000)


    async def _maybe_rotate_ua(self):
        if self.ua_mode == 'per-request':
            import random
            ua = random.choice(self._ua_pool)
            await self.context.set_extra_http_headers({'User-Agent': ua})


    async def _export_trace(self, tag: str):
        if not self.trace_on_hit:
            return None
        trace_dir = self.outdir / 'trace'
        trace_dir.mkdir(parents=True, exist_ok=True)
        path = trace_dir / f'trace_{tag}.zip'
        try:
            await self.context.tracing.stop(path=path.as_posix())
            # Restart tracing to continue capturing after export
            await self.context.tracing.start(screenshots=True, snapshots=True, sources=True)
            return path.as_posix()
        except Exception:
            return None


    async def warmup(self, url: str):
        import asyncio as _asyncio
        if self.warmup_requests <= 0:
            return
        for _ in range(self.warmup_requests):
            try:
                await self._maybe_rotate_ua()
                await self.page.goto(url, wait_until='domcontentloaded')
                await _asyncio.sleep(max(0, self.warmup_wait_ms)/1000)
            except Exception:
                pass
