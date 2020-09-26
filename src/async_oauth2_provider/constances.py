from .structures import CaseInsensitiveDict


def _default_headers() -> CaseInsensitiveDict:
    return CaseInsensitiveDict(
        {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
    )


default_headers = _default_headers()
