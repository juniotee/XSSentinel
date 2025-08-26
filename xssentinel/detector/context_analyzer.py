from typing import List, Dict, Any

def summarize_reflection(html: str, marker: str) -> Dict[str, Any]:
    reflected = marker in html
    return {
        'reflected': reflected,
        'evidence': 'marker found in DOM' if reflected else None,
    }
