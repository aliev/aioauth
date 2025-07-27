"""
Configuration settings for aioauth server instance.

```python
from aioauth import config
```
"""

from dataclasses import dataclass


@dataclass
class Settings:
    """Configuration options that is used by the Server class."""

    TOKEN_EXPIRES_IN: int = 24 * 60 * 60
    """Access token lifetime in seconds. Defaults to 24 hours."""

    REFRESH_TOKEN_EXPIRES_IN: int = TOKEN_EXPIRES_IN * 2
    """Refresh token lifetime in seconds. Defaults to TOKEN_EXPIRES_IN * 2 (48 hours)."""

    ISSUE_REFRESH_TOKEN_IMPLICIT_GRANT: bool = True
    """Issue refresh tokens during implicit grant dialog.

    Note:
        This flag can be used, when sets to `True`, to strictly meet the requirements
        described in section 4.2 of the RFC 6749 regarding the issuance of refresh
        tokens during grant type "Implicit Grant". In particular, as stated in section
        4.2.2 of that RFC:

        > 4.2.2.  Access Token Response
        >
        > If the resource owner grants the access request, the authorization
        > server issues an access token and delivers it to the client by adding
        > the following parameters to the fragment component of the redirection
        > URI using the "application/x-www-form-urlencoded" format, per
        > Appendix B:
        >
        > [...]
        >
        > The authorization server MUST NOT issue a refresh token.

        Reference links:

        - [https://datatracker.ietf.org/doc/html/rfc6749#section-4.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2)
        - [https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2)
    """

    AUTHORIZATION_CODE_EXPIRES_IN: int = 5 * 60
    """Authorization code lifetime in seconds. Defaults to 5 minutes."""

    INSECURE_TRANSPORT: bool = False
    """Allow connections over SSL only.

    Note:
        When this option is disabled server will raise "HTTP method is
        not allowed" error when attempting to access the server without
        a valid SSL tunnel.
    """

    ERROR_URI: str = ""
    """URI to redirect resource owner when server encounters error."""

    AVAILABLE: bool = True
    """Boolean indicating whether or not the server is available."""

    DEBUG: bool = False
