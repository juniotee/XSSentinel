from pathlib import Path

def load_base_payloads():
    here = Path(__file__).parent
    with open(here / 'base_payloads.txt', 'r', encoding='utf-8') as f:
        lines = [ln.strip() for ln in f.readlines() if ln.strip() and not ln.strip().startswith('#')]
    return lines
