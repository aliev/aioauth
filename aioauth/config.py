"""
.. code-block:: python

    from aioauth import config

Configuration settings for aioauth server instance.

----
"""

from dataclasses import dataclass


@dataclass
class Settings:
    """Configuration options that is used by the Server class."""

    TOKEN_EXPIRES_IN: int = 24 * 60 * 60
    """Access token lifetime in seconds. Defaults to 24 hours."""

    REFRESH_TOKEN_EXPIRES_IN: int = TOKEN_EXPIRES_IN * 2
    """Refresh token lifetime in seconds. Defaults to TOKEN_EXPIRES_IN * 2 (48 hours)."""

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
