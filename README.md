# XSSentinel — Modern XSS Scanner (Python + Playwright)

**XSSentinel** is a modern **XSS** scanner designed for dynamic apps (SPAs, DOM-heavy UIs). It focuses on **actual execution** (Reflected & DOM-based XSS), **WAF evasion**, **CSP awareness**, and **reproducible evidence** (trace/HAR/screenshots).

> Goal: measurably increase real-world XSS findings by prioritizing execution signals, DOM context, and CSP-compatible payloads.

---

## ✨ Highlights

- **JS-aware engine (Playwright + Python)**: full JS rendering, DOM events, iframes, shadow DOM, `hashchange`.
- **Multi-context fuzzing**: forms (named inputs), **URL parameter fuzzing** (preserving existing query) + **fragment (`#`) fallback** for SPA routers.
- **CSP-aware payload catalog**: per-origin CSP capture (header/meta) + template metadata:
  `requires_inline`, `needs_data`, `needs_blob`, `context_tags` (html_text, html_attr, js_string, url, svg, style, srcdoc).
- **WAF evasion (polymorphic)**: case shuffling, zero-width, comment noise, selective HTML/entity/URL mangling, keyword splitting, `setTimeout`/`Function` wrappers, pacing + **jitter**, **User-Agent rotation**.
- **Sink-driven heuristics**: hooks for `document.write/writeln`, `innerHTML`, `insertAdjacentHTML`, `setAttribute(on*)`, `location.assign/replace`, `history.pushState/replaceState`; payload ordering adapts to observed sinks.
- **Evidence & reproducibility**: screenshots, **Playwright trace per hit** (`--trace-on-hit`), **session HAR**, deterministic `--seed`.
- **Reporting & scoring**: `report.json` + `report.html` with **Executive Summary**, **Severity/Score**, sink counts, links to **trace.zip** / evidence; optional **Executive PDF** (`--export-pdf`). Severity policy: `default | owasp | cvss`.

---

## ⚙️ Install

```bash
python -m venv .venv
# Linux/Mac
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python -m playwright install
```

> **Note:** the package folder is currently `xssentinel` (backward-compatible). CLI examples below use that module path.

---

## ▶️ Usage

```bash
python -m xssentinel.cli.main   --url https://authorized-target.tld/app?foo=bar   --headless   --csp-aware   --fuzz-url --max-params 8 --backoff-ms 500   --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"   --ua-rotate per-request   --warmup-requests 2 --warmup-wait-ms 800   --pacing-ms 220 --jitter-pct 0.35   --max-payloads 300   --trace-on-hit   --severity-policy owasp   --export-pdf   --seed 1337   --out ./results
```

**Key flags**

- **Scanning:** `--fuzz-url`, `--max-params`, `--max-forms`  
- **CSP-aware:** `--csp-aware`  
- **WAF/stealth:** `--user-agent`, `--ua-rotate session|per-request`, `--pacing-ms`, `--jitter-pct`, `--warmup-requests`, `--warmup-wait-ms`  
- **Reproducibility:** `--seed`, `--max-payloads`  
- **Evidence:** `--trace-on-hit` (writes `trace/trace_*.zip`), session HAR (`session.har`)  
- **Reports:** `--severity-policy default|owasp|cvss`, `--export-pdf`

---

## 📤 Outputs

- `results/report.json` (findings + summary)  
- `results/report.html` (Executive Summary + Severity/Score/Trace/Sinks)  
- `results/executive_summary.pdf` (optional)  
- `results/evidences/*.png`, `results/trace/trace_*.zip`, `results/session.har`

---

## 🧠 How it works (short)

1. **CSP-aware selection**: capture CSP (header/meta), then choose payloads viable under that policy (inline/data/blob).  
2. **Fuzzing**: forms and URL params; if no signal, **fragment fallback** with forced `hashchange` for SPA routers.  
3. **Execution detection**: init script with `MutationObserver` + title signal; **sink hooks** collect DOM sink activity.  
4. **WAF tuning**: pacing + jitter, UA rotation, warm-up navigations.  
5. **Evidence**: screenshot, trace/HAR, severity/score.

---

## 🧪 Practical tips

- Start with `--csp-aware` + `--fuzz-url` and a sane `--max-payloads` (200–400).  
- In sensitive environments, enable `--pacing-ms` + `--jitter-pct` and UA rotation.  
- Fix `--seed` for reproducible evidence.  
- Use `--trace-on-hit` to replay flows in Playwright Trace Viewer.  
- In CI/CD, gate on severity using `report.json` as the source of truth.

---

## 📦 Project layout

```
xssentinel/
  cli/main.py                # CLI (flow, scoring, exports)
  crawler/browser_engine.py  # Playwright, fuzzing, trace/HAR, stealth
  detector/sandbox_executor.py  # init script, sink hooks, exec signal
  payloads/
    wordlists/*.txt          # contextual catalog
    evasions.py              # WAF evasion transforms
    mutator.py               # CSP-aware selection + sink-aware ordering
  reports/
    reporter.py              # JSON/HTML + minimalist executive PDF
    scoring.py               # score 0–100 + severity (default/owasp/cvss)
    templates/report.html    # report template
  utils/
    csp.py, encoder.py
```

---

## ⚖️ Legal & ethics

Use **only** for **authorized testing**. You are responsible for legal compliance (privacy, contracts, ToS).

---

## 🛣️ Roadmap

- Finer-grained CSP catalog (by origin/route & sink signals)  
- SPA framework fingerprints and targeted vectors  
- Multi-URL crawling with rate limits & prioritization  
- Payload plugin interface  
- Rich executive PDF (charts, timeline, param/field ranking)

---

## 🤝 Contributing

PRs and issues welcome. Python 3.10+, clear typing and comments (English). Include minimal repros; respect ethical scope.

---

## 📜 License

MIT — see `LICENSE`.
