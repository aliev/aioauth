=====================
Async OAuth2 Provider
=====================


.. image:: https://img.shields.io/pypi/v/async_oauth2_provider.svg
        :target: https://pypi.python.org/pypi/async_oauth2_provider

.. image:: https://img.shields.io/travis/aliev/async_oauth2_provider.svg
        :target: https://travis-ci.com/aliev/async_oauth2_provider

.. image:: https://readthedocs.org/projects/async-oauth2-provider/badge/?version=latest
        :target: https://async-oauth2-provider.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status


.. image:: https://pyup.io/repos/github/aliev/async_oauth2_provider/shield.svg
     :target: https://pyup.io/repos/github/aliev/async_oauth2_provider/
     :alt: Updates


Asynchronous OAuth 2.0 framework for Python 3
---------------------------------------------

``async-oauth2-provider`` implements `OAuth 2.0`_ protocol and can be used
in `FastAPI / Starlette`_, aiohttp or any other asynchronous frameworks. It
can work with any databases like ``MongoDB``, ``PostgreSQL``, ``MySQL``
and ORMs like `gino`_, `sqlalchemy`_, `databases`_ over simple `DBBase`_
interface.

Why this project exists?
------------------------

There are few great OAuth frameworks for Python like `oauthlib`_ and
`authlib`_, but they do not support asyncio because rewriting these
libraries to asyncio is a big challenge.

`Here`_ we implemented an integration example with FastAPI / Starlette.
If you want to add more examples, please welcome to `contribution`_!

Settings and defaults
---------------------

+---------------------------------------+---------------+---------------------------------------------------------------------------------------------------------------------+
| Setting                               | Default value | Description                                                                                                         |
+ ===================================== + ============= | =================================================================================================================== |
| OAUTH2_TOKEN_EXPIRES_IN               | 86400         | Access token lifetime. Default value in seconds.                                                                    |
+---------------------------------------+---------------+---------------------------------------------------------------------------------------------------------------------+
| OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN  | 300           | Authorization code lifetime. Default value in seconds.                                                              |
+---------------------------------------+---------------+---------------------------------------------------------------------------------------------------------------------+
| OAUTH2_INSECURE_TRANSPORT             | False         | Allow connections over SSL only. When this option is disabled server will raise "HTTP method is not allowed" error. |
+---------------------------------------+---------------+---------------------------------------------------------------------------------------------------------------------+

Supported RFCs
--------------

-  ☒ `The OAuth 2.0 Authorization Framework`_
-  ☐ `Proof Key for Code Exchange by OAuth Public Clients`_
-  ☐ `OAuth 2.0 Token Introspection`_

.. _The OAuth 2.0 Authorization Framework: https://tools.ietf.org/html/rfc6749
.. _Proof Key for Code Exchange by OAuth Public Clients: https://tools.ietf.org/html/rfc7636
.. _OAuth 2.0 Token Introspection: https://tools.ietf.org/html/rfc7662
.. _oauthlib: https://github.com/oauthlib/oauthlib
.. _authlib: https://github.com/lepture/authlib
.. _OAuth 2.0: https://tools.ietf.org/html/rfc6749
.. _FastAPI / Starlette: examples
.. _gino: https://python-gino.org/
.. _sqlalchemy: https://www.sqlalchemy.org/
.. _databases: https://pypi.org/project/databases/
.. _DBBase: src/async_oauth2_provider/db.py
.. _Here: examples
.. _contribution: CONTRIBUTING.rst

License
-------

* Free software: MIT license
* Documentation: https://async-oauth2-provider.readthedocs.io.
