"""
.. code-block:: python
    from aioauth import structures
Structures that are used throughout the project.
----
"""


from collections import UserDict


class CaseInsensitiveDict(UserDict):
    """
    A case-insensitive ``dict``-like object.
    Example:
        .. code-block:: python
            from aioauth.structures import CaseInsensitiveDict
            d = CaseInsensitiveDict({"hello": "world"})
            d['hello'] == 'world' # >>> True
            d['Hello'] == 'world' # >>> True
            d['hElLo'] == 'world' # >>> True
    """

    def __setitem__(self, key, value):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())
