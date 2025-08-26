import urllib.parse

def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe='')

def html_escape(s: str) -> str:
    return (s
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))

def js_string_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace("'", "\\'").replace('"', '\\"')
