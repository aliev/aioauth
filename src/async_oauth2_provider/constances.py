from typing import Dict


def _default_headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }


default_headers = _default_headers()
