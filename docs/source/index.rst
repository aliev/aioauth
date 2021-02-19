Getting Started
===============

aioauth is a spec-compliant OAuth 2.0 asynchronous Python module. aioauth works out-of-the-box with asynchronous server frameworks like FastAPI, Starlette, aiohttp, and others, as well as asynchronous database modules like Motor (MongoDB), aiopg (PostgreSQL), aiomysql (MySQL), or ORMs like Gino, sqlalchemy, or Tortoise. 

The magic of aioauth is its plug-and-play methods that allow the use of virtually any server or database framework.

Installing
----------

To install aioauth at the command line:

.. code-block::

   $ pip install aioauth

To install pre-releases:

.. code-block::

   $ pip install git+https://github.com/aliev/aioauth


Supported RFC
-------------

aioauth supports the following RFCs:

* `RFC 6749 - The OAuth 2.0 Authorization Framework <https://tools.ietf.org/html/rfc6749>`_
* `RFC 7662 - OAuth 2.0 Token Introspection <https://tools.ietf.org/html/rfc7662>`_
* `RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients <https://tools.ietf.org/html/rfc7636>`_

----

Sections
========

.. include:: contents.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
