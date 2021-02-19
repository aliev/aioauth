"""
.. code-block:: python

    from aioauth import config

Configuration settings for aioauth server instance.
"""

from types import SimpleNamespace


class Settings(SimpleNamespace):
    """Configuration options that is used by the Server class."""

    TOKEN_EXPIRES_IN: int = 86400
    """Access token lifetime in seconds."""

    AUTHORIZATION_CODE_EXPIRES_IN: int = 300
    """Authorization code lifetime in seconds."""

    INSECURE_TRANSPORT: bool = False
    """Allow connections over SSL only.

    Note:
        When this option is disabled server will raise"HTTP method is not allowed"error when
        attempting to access the server without a valid SSL tunnel.
    """

    ERROR_URI: str = ""
    """URI to redirect resource owner when server encounters error."""

    AVAILABLE: bool = True
    """Boolean indicating whether or not the server is available."""
