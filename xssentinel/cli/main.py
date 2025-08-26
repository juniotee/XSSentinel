import argparse, asyncio, json, os
from pathlib import Path
from rich import print as rprint
from rich.table import Table
from rich.console import Console
from ..crawler.browser_engine import BrowserEngine
from ..reports import reporter
from ..reports.scoring import score_hit, summarize
from ..reports.reporter import save_pdf_summary

def parse_args():
    p = argparse.ArgumentParser(description='XSSentinel - XSS scanner (prototype)')
    p.add_argument('--url', required=True, help='Target URL')
    p.add_argument('--headless', dest='headless', action='store_true', help='Run in headless mode (default)')
    p.add_argument('--no-headless', dest='headless', action='store_false', help='Show the browser')
    p.set_defaults(headless=True)
    p.add_argument('--timeout', type=int, default=15000, help='Timeout per operation (ms)')
    p.add_argument('--auth-cookies', type=str, default=None, help='Path to JSON cookies file')
    p.add_argument('--max-forms', type=int, default=10, help='Max number of forms to fuzz on the page')
    p.add_argument('--out', type=str, default='./xssentinel_out', help='Output directory')
    # Stealth / control
    p.add_argument('--user-agent', type=str, default=None, help='Custom User-Agent (stealth)')
    p.add_argument('--pacing-ms', type=int, default=0, help='Base delay between payloads (ms) to reduce WAF noise')
    p.add_argument('--jitter-pct', type=float, default=0.0, help='Random jitter fraction for pacing (e.g., 0.3 = ±30%)')
    p.add_argument('--ua-rotate', type=str, default=None, choices=['session','per-request'], help='Rotate User-Agents (session = once, per-request = each request)')
    p.add_argument('--warmup-requests', type=int, default=0, help='Number of warm-up navigations before fuzzing')
    p.add_argument('--warmup-wait-ms', type=int, default=500, help='Delay between warm-up navigations (ms)')
    p.add_argument('--max-payloads', type=int, default=0, help='Max payloads per field/param (0 = unlimited)')
    p.add_argument('--seed', type=int, default=None, help='Random seed for reproducibility')
    # Features
    p.add_argument('--csp-aware', action='store_true', help='Adapt payload selection to observed CSP (avoid inline when blocked)')
    p.add_argument('--fuzz-url', action='store_true', help='Enable URL parameter fuzzing (in addition to forms)')
    p.add_argument('--max-params', type=int, default=8, help='Max number of URL params to fuzz')
    p.add_argument('--backoff-ms', type=int, default=500, help='Initial backoff (ms) for 403/429 during URL fuzzing')
    p.add_argument('--trace-on-hit', action='store_true', help='Export a Playwright trace ZIP per hit')
    p.add_argument('--severity-policy', type=str, default='default', choices=['default','owasp','cvss'], help='Severity policy mapping')
    p.add_argument('--export-pdf', action='store_true', help='Export minimalist Executive Summary PDF')
    return p.parse_args()

async def run():
    args = parse_args()
    if args.seed is not None:
        import random
        random.seed(args.seed)

    outdir = Path(args.out)
    evid_dir = outdir / 'evidences'
    templates_src = Path(__file__).resolve().parent.parent / 'reports' / 'templates'
    templates_dst = outdir / 'templates'
    templates_dst.mkdir(parents=True, exist_ok=True)
    # Copy the HTML template for standalone editing
    for name in os.listdir(templates_src):
        src = templates_src / name
        dst = templates_dst / name
        if src.is_file():
            dst.write_text(src.read_text(encoding='utf-8'), encoding='utf-8')

    marker = os.environ.get('XSSPROBE_MARKER') or os.urandom(4).hex()
    results = []

    async with BrowserEngine(headless=args.headless,
                             timeout_ms=args.timeout,
                             evidence_dir=evid_dir,
                             user_agent=args.user_agent,
                             pacing_ms=args.pacing_ms,
                             jitter_pct=args.jitter_pct,
                             ua_mode=(args.ua_rotate or 'session'),
                             trace_on_hit=args.trace_on_hit,
                             outdir=outdir,
                             warmup_requests=args.warmup_requests,
                             warmup_wait_ms=args.warmup_wait_ms) as be:
        cookies = None
        if args.auth_cookies and Path(args.auth_cookies).exists():
            try:
                cookies = json.loads(Path(args.auth_cookies).read_text(encoding='utf-8'))
                await be.set_cookies(cookies, args.url)
            except Exception as e:
                rprint(f'[yellow]Warning[/yellow]: failed to load cookies: {e}')

        rprint(f'[cyan]Target[/cyan]: {args.url}  [dim]marker={marker}[/dim]')

        # Navigate once to capture CSP and perform warmup
        await be.navigate(args.url)
        csp_info = be.get_csp_info() if args.csp_aware else None

        from ..payloads.mutator import mutate as mutate_func
        # Initial sink hints (empty); will be updated after first batch if needed
        sink_hints = []
        payloads = mutate_func(marker, csp_info=csp_info, sink_hints=sink_hints)

        if args.max_payloads and len(payloads) > args.max_payloads:
            from random import sample
            payloads = sample(payloads, args.max_payloads)

        # Fuzz forms
        res_forms = await be.fuzz_forms(args.url, marker, payloads, max_forms=args.max_forms)
        results.extend(res_forms)

        # Optional URL fuzzing
        if args.fuzz_url:
            res_url = await be.fuzz_url_params(args.url, marker, payloads, max_params=args.max_params, backoff_ms=args.backoff_ms)
            results.extend(res_url)

        # Quick second pass prioritized by observed sinks (if any)
        try:
            sink_names = set()
            for r in results:
                for s in (r.get('sinks') or []):
                    nm = (s.get('name') or '')
                    if nm:
                        sink_names.add(nm)
            sink_hints = sorted(sink_names)[:6]
            if sink_hints:
                rprint(f"[dim]Sink hints: {', '.join(sink_hints)}[/dim]")
                payloads2 = mutate_func(marker, csp_info=csp_info, sink_hints=list(sink_hints))
                if args.max_payloads and len(payloads2) > args.max_payloads:
                    from random import sample
                    payloads2 = sample(payloads2, args.max_payloads)
                res_forms2 = await be.fuzz_forms(args.url, marker, payloads2, max_forms=max(3, args.max_forms//2))
                results.extend(res_forms2)
        except Exception as e:
            rprint(f"[yellow]Hint pass skipped[/yellow]: {e}")

    # Scoring and summary
    results = [score_hit(r, policy=args.severity_policy) for r in results]
    summary = summarize([r for r in results if r.get('executed') or r.get('reflected')])

    # Save reports
    reporter.save_json(results, outdir, summary=summary)
    reporter.save_html(results, outdir, summary=summary)
    if args.export_pdf:
        save_pdf_summary(summary, outdir)

    # Terminal summary
    hits = [r for r in results if r.get('executed') or r.get('reflected')]
    table = Table(title='Summary')
    table.add_column('Severity')
    table.add_column('Score')
    table.add_column('URL')
    table.add_column('Field/Param')
    table.add_column('Signals')
    for h in hits[:50]:
        sig = []
        if h.get('executed'): sig.append('executed')
        if h.get('reflected'): sig.append('reflected')
        table.add_row(h.get('severity',''), str(h.get('score','')), h.get('url',''), h.get('field') or h.get('param',''), ','.join(sig))
    console = Console()
    console.print(table)
    rprint(f'🏁 Reports saved at: [bold]{outdir}[/bold]')

if __name__ == '__main__':
    asyncio.run(run())
