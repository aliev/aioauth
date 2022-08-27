"""
.. code-block:: python

    from aioauth import collections

Collections that are used throughout the project.

----
"""

from collections import UserDict


class HTTPHeaderDict(UserDict):
    """
    :param headers:
        An iterable of field-value pairs. Must not contain multiple field names
        when compared case-insensitively.

    :param kwargs:
        Additional field-value pairs to pass in to ``dict.update``.

    A ``dict`` like container for storing HTTP Headers.

    Example:

    .. code-block:: python

        from aioauth.collections import HTTPHeaderDict
        d = HTTPHeaderDict({"hello": "world"})
        d['hello'] == 'world' # >>> True
        d['Hello'] == 'world' # >>> True
        d['hElLo'] == 'world' # >>> True
    """

    def __setitem__(self, key: str, value: str):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key: str):
        return super().__getitem__(key.lower())
