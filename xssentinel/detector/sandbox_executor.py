import asyncio
from typing import Dict, Any
from playwright.async_api import Page


HOOKS_SCRIPT = '''
(() => {
  try {
    window.__xssentinel_sinks = window.__xssentinel_sinks || [];
    const logSink = (name, detail) => {
      try {
        window.__xssentinel_sinks.push({name, detail: String(detail||''), ts: Date.now()});
      } catch(e){}
    };

    // document.write / writeln
    try {
      const _w = document.write.bind(document);
      document.write = function(...args){ logSink('document.write', args.join('')); return _w(...args); };
      const _wl = document.writeln.bind(document);
      document.writeln = function(...args){ logSink('document.writeln', args.join('')); return _wl(...args); };
    } catch(e){}

    // Element.innerHTML setter
    try {
      const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      if (desc && desc.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
          set: function(v){ logSink('innerHTML', v); return desc.set.call(this, v); },
          get: desc.get,
          configurable: true
        });
      }
    } catch(e){}

    // insertAdjacentHTML
    try {
      const _ins = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function(pos, html){ logSink('insertAdjacentHTML', html); return _ins.call(this, pos, html); };
    } catch(e){}

    // setAttribute for event handlers
    try {
      const _sa = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function(name, val){ if (String(name||'').startsWith('on')) logSink('setAttribute', name+'='+String(val||'')); return _sa.call(this, name, val); };
    } catch(e){}

    // location.*
    try {
      const wrapNav = (fnName) => {
        const _fn = window.location[fnName].bind(window.location);
        window.location[fnName] = function(v){ logSink('location.'+fnName, v); return _fn(v); };
      };
      ['assign','replace'].forEach(wrapNav);
    } catch(e){}

    // History API
    try {
      const _ps = history.pushState.bind(history);
      history.pushState = function(...args){ logSink('history.pushState', args[2] || ''); return _ps(...args); };
      const _rs = history.replaceState.bind(history);
      history.replaceState = function(...args){ logSink('history.replaceState', args[2] || ''); return _rs(...args); };
    } catch(e){}
  } catch(e){}
})();
'''

INIT_SCRIPT_TEMPLATE = """
(() => {
  try {
    const marker = '%MARKER%';
    const markHit = () => {
      try { document.title = 'xssentinel-hit-' + marker; } catch(e){}
      try { window.__xssentinel_hits = (window.__xssentinel_hits||[]); window.__xssentinel_hits.push(marker); } catch(e){}
    };
    const obs = new MutationObserver(() => {
      try {
        const found = document.documentElement && document.documentElement.innerHTML && document.documentElement.innerHTML.indexOf(marker) !== -1;
        if (found) markHit();
      } catch(e){}
    });
    obs.observe(document.documentElement || document, {subtree:true, childList:true, attributes:true, characterData:true});
    // Sinal periódico caso o JS da página reescreva o título
    setInterval(() => {
      if ((window.__xssentinel_hits||[]).includes(marker)) {
        try { if (!document.title.includes('xssentinel-hit-'+marker)) document.title = 'xssentinel-hit-' + marker; } catch(e){}
      }
    }, 500);
  } catch(e){}
})();
""";

async def wait_for_execution_signal(page: Page, marker: str, timeout_ms: int = 4000) -> bool:
    # Verifica se document.title sinalizou execução
    try:
        await page.wait_for_function("document.title.includes('xssentinel-hit-' + marker)", timeout=timeout_ms)
        return True
    except Exception:
        return False

async def inject_init_script(page: Page, marker: str):
    script = INIT_SCRIPT_TEMPLATE.replace('%MARKER%', marker.replace("'","\\'"))
    await page.add_init_script(script)
    await page.add_init_script(HOOKS_SCRIPT)


async def get_sink_log(page: Page):
    try:
        return await page.evaluate("() => (window.__xssentinel_sinks||[])")
    except Exception:
        return []
