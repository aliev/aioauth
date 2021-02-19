""" 
.. code-block:: python

    from aioauth import constances

Constants that are used throughout the project.
"""

from .structures import CaseInsensitiveDict


default_headers = CaseInsensitiveDict(
    {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
)
"""
The authorization server MUST include the HTTP "Cache-Control"
response header field [RFC2616] with a value of "no-store" in any
response containing tokens, credentials, or other sensitive
information, as well as the "Pragma" response header field [RFC2616]
with a value of "no-cache".
"""  # pylint: disable=W0105
