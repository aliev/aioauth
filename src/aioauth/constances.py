from .structures import CaseInsensitiveDict


def _default_headers() -> CaseInsensitiveDict:
    """The authorization server MUST include the HTTP "Cache-Control"
    response header field [RFC2616] with a value of "no-store" in any
    response containing tokens, credentials, or other sensitive
    information, as well as the "Pragma" response header field [RFC2616]
    with a value of "no-cache".
    """
    return CaseInsensitiveDict(
        {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
    )


default_headers = _default_headers()
