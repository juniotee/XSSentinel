from typing import Dict, Any, List

# Sink weight mapping (rough impact heuristics)
SINK_WEIGHTS = {
    'document.write': 25,
    'document.writeln': 20,
    'innerHTML': 22,
    'insertAdjacentHTML': 22,
    'setAttribute': 18,            # event handler attributes
    'location.assign': 12,
    'location.replace': 12,
    'history.pushState': 8,
    'history.replaceState': 8,
}

def score_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a numeric risk score and severity label for a single finding.
    Signals considered: executed/reflected, sink logs, http status, evidence presence.
    Returns the hit dict with 'score' and 'severity' fields added.
    """
    score = 0

    # Primary signals
    if hit.get('executed'):
        score += 80
    elif hit.get('reflected'):
        score += 30

    # Sinks
    sinks = hit.get('sinks') or []
    names = [ (s.get('name') or '') for s in sinks ]
    for nm in names:
        for key, w in SINK_WEIGHTS.items():
            if nm.startswith(key):
                score += w

    # Evidence
    if hit.get('screenshot'):
        score += 5
    if hit.get('trace'):
        score += 5

    # HTTP status confidence
    status = hit.get('status')
    if isinstance(status, int):
        if 200 <= status < 300:
            score += 5
        elif 400 <= status < 500:
            score -= 10
        elif 500 <= status < 600:
            score -= 5

    # Clamp to [0, 100]
    score = max(0, min(100, score))

    # Severity bands
    if score >= 90:
        sev = 'Critical'
    elif score >= 70:
        sev = 'High'
    elif score >= 40:
        sev = 'Medium'
    elif score >= 15:
        sev = 'Low'
    else:
        sev = 'Info'

    hit['score'] = score
    hit['severity'] = sev
    return hit

def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build an executive summary: severity breakdown, mode stats, top items.
    """
    out = {
        'counts_by_severity': {'Critical':0, 'High':0, 'Medium':0, 'Low':0, 'Info':0},
        'counts_by_mode': {},
        'top_findings': [],
        'total_findings': len(findings),
    }
    # Counts
    for f in findings:
        sev = f.get('severity', 'Info')
        out['counts_by_severity'][sev] = out['counts_by_severity'].get(sev, 0) + 1
        mode = f.get('mode') or 'form'
        out['counts_by_mode'][mode] = out['counts_by_mode'].get(mode, 0) + 1

    # Top 5 by score (break ties by executed/reflected and presence of sinks)
    sorted_hits = sorted(findings, key=lambda x: (x.get('score',0), x.get('executed', False), len(x.get('sinks') or [])), reverse=True)
    out['top_findings'] = [{
        'url': h.get('url'),
        'field': h.get('field') or h.get('param'),
        'mode': h.get('mode', 'form'),
        'severity': h.get('severity'),
        'score': h.get('score'),
        'executed': h.get('executed'),
        'reflected': h.get('reflected'),
        'payload': h.get('payload'),
        'trace': h.get('trace'),
        'screenshot': h.get('screenshot'),
    } for h in sorted_hits[:5]]

    return out
