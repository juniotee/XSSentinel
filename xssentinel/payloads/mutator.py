
from typing import List, Tuple
from pathlib import Path
from ..utils.encoder import url_encode, html_escape
from .evasions import compose_evasions

WL_DIR = Path(__file__).parent / 'wordlists'

# Catalog: filename -> requires_inline

# Catalog metadata: filename -> capability flags
# requires_inline: uses inline scripts/handlers
# needs_data: benefits from data: allowance
# needs_blob: benefits from blob: allowance
# context_tags: rough categorization for sink alignment (html_text, html_attr, event, js_string, url, svg, style, polyglot, srcdoc)
CATALOG = {
    'html_text.txt':        {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['html_text']},
    'html_attr.txt':        {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['html_attr','event']},
    'html_event.txt':       {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['event']},
    'js_string.txt':        {'requires_inline': False, 'needs_data': False, 'needs_blob': False, 'context_tags': ['js_string']},
    'url_query.txt':        {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['url']},
    'svg_mathml.txt':       {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['svg']},
    'style_css.txt':        {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['style','event']},
    'polyglots.txt':        {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['polyglot']},
    'templates.txt':        {'requires_inline': True,  'needs_data': False, 'needs_blob': False, 'context_tags': ['html_text','html_attr','event']},
    'data_blob_srcdoc.txt': {'requires_inline': True,  'needs_data': True,  'needs_blob': False, 'context_tags': ['srcdoc','url']},
}
def _iter_templates_with_meta() -> Tuple[str, bool]:
    for p in WL_DIR.glob('*.txt'):
        req_inline = CATALOG.get(p.name, True)
        for ln in p.read_text(encoding='utf-8').splitlines():
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            yield ln, req_inline

def _transformations(s: str) -> List[str]:
    outs = {s}
    outs.add(url_encode(s))
    outs.add(url_encode(url_encode(s)))
    outs.add(html_escape(s))
    return list(outs)

def mutate(marker: str, csp_info: dict | None = None, sink_hints: list[str] | None = None) -> List[str]:
    title_expr = f"document.title='xssentinel-{marker}'"

    # Choose templates based on CSP (if provided)
    if csp_info and not csp_info.get('allows_inline', True):
        templates = [tpl for tpl, req in _iter_templates_with_meta() if not req]
    else:
        templates = [tpl for tpl, _ in _iter_templates_with_meta()]

    # Apply evasions (which may wrap {JSCMD}); then resolve any leftover placeholder
    evasive = [compose_evasions(tpl.replace('{MARKER}', marker), title_expr) for tpl in templates]
    evasive = [e.replace('{JSCMD}', title_expr) for e in evasive]

    mutated = set()
    for base in evasive:
        for variant in _transformations(base):
            mutated.add(variant)
        mutated.add(base.replace('"', "'"))
        mutated.add(base.replace("'", '"'))
        mutated.add(base.replace('<', '<<'))
        mutated.add(base.upper())

    return list(mutated)
