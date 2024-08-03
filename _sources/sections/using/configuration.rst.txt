Configuration
=============

All aioauth settings are made through :py:class:`aioauth.config.Settings` class.

Defaults

+----------------------------------------+---------------+----------------------------------------------------------------+
| Setting                                | Default value | Description                                                    |
|                                        |               |                                                                |
+========================================+===============+================================================================+
|         TOKEN_EXPIRES_IN               | 86400         | Access token lifetime.                                         |
+----------------------------------------+---------------+----------------------------------------------------------------+
|         AUTHORIZATION_CODE_EXPIRES_IN  | 300           | Authorization code lifetime.                                   |
+----------------------------------------+---------------+----------------------------------------------------------------+
|         INSECURE_TRANSPORT             | False         | Allow connections over SSL only. When this option is disabled  |
|                                        |               | server will raise "HTTP method is not allowed" error.          |
+----------------------------------------+---------------+----------------------------------------------------------------+

the default settings can be changed as follows:

.. code-block:: python

    import os
    from aioauth.config import Settings

    settings = Settings(
        INSECURE_TRANSPORT=not os.getenv('DEBUG', False)
    )

this example disables checking for insecure transport, depending on the debug mode of the current environment.

The :py:class:`aioauth.requests.Request` consumes an instance of the :py:class:`aioauth.config.Settings` class:

.. code-block:: python

    import os
    from aioauth.config import Settings
    from aioauth.requests import Request

    settings = Settings(
        INSECURE_TRANSPORT=not os.getenv('DEBUG', False)
    )

    request = Request(
        settings=settings,
        ...
    )
