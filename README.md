## Asynchronous OAuth 2.0 framework for Python 3

[![Build Status](https://github.com/aliev/aioauth/workflows/CI/badge.svg?branch=master)](https://github.com/aliev/aioauth/actions/workflows/ci.yml?query=branch%3Amaster)
[![Coverage](https://badgen.net/codecov/c/github/aliev/aioauth)](https://app.codecov.io/gh/aliev/aioauth)
[![License](https://img.shields.io/github/license/aliev/aioauth)](https://github.com/aliev/aioauth/blob/master/LICENSE)
[![PyPi](https://badgen.net/pypi/v/aioauth)](https://pypi.org/project/aioauth/)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/)

`aioauth` implements [OAuth 2.0 protocol](https://tools.ietf.org/html/rfc6749) and can be used in asynchronous frameworks like [FastAPI / Starlette](https://github.com/tiangolo/fastapi), [aiohttp](https://github.com/aio-libs/aiohttp). It can work with any databases like `MongoDB`, `PostgreSQL`, `MySQL` and ORMs like [gino](https://python-gino.org/), [sqlalchemy](https://www.sqlalchemy.org/) or [databases](https://pypi.org/project/databases/) over simple [BaseStorage](aioauth/storage.py) interface.

## Why this project exists?

There are few great OAuth frameworks for Python like [oauthlib](https://github.com/oauthlib/oauthlib) and [authlib](https://github.com/lepture/authlib), but they do not support asyncio and rewriting these libraries to asyncio is a significant challenge (see issues [here](https://github.com/lepture/authlib/issues/63) and [here](https://github.com/oauthlib/oauthlib/issues/415)).

## Supported RFCs

- [x] [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [X] [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [X] [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [x] OpenID support

## Installation

```
python -m pip install aioauth
```

## FastAPI

FastAPI integration stored on separated [aioauth-fastapi](https://github.com/aliev/aioauth-fastapi) repository and can be installed via the command:

```
python -m pip install aioauth[fastapi]
```

[aioauth-fastapi](https://github.com/aliev/aioauth-fastapi) repository contains demo example which I recommend to look.

## [API Reference and User Guide](https://aliev.me/aioauth/)
