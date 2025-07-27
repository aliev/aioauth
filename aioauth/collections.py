"""
```python
from aioauth import collections
```


Collections that are used throughout the project.

----
"""

from collections import UserDict
from typing import Any


class HTTPHeaderDict(UserDict):
    """
    :param headers:
        An iterable of field-value pairs. Must not contain multiple field names
        when compared case-insensitively.

    :param kwargs:
        Additional field-value pairs to pass in to ``dict.update``.

    A ``dict`` like container for storing HTTP Headers.

    Example:

    ```python
from aioauth.collections import HTTPHeaderDict
        d = HTTPHeaderDict({"hello": "world"})
        d['hello'] == 'world' # >>> True
        d['Hello'] == 'world' # >>> True
        d['hElLo'] == 'world' # >>> True
    ```
    """

    def __init__(self, dict=None, **kwargs):
        """Object initialization."""
        super().__init__(dict, **kwargs)
        self.data = {k.lower(): v for k, v in self.data.items()}

    def __setitem__(self, key: str, value: str):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key: str):
        return super().__getitem__(key.lower())

    def __delitem__(self, key: str):
        """Item deletion."""
        return super().__delitem__(key.lower())

    def get(self, key: str, default: Any = None):
        """Case-insentive get."""
        try:
            return self[key]
        except KeyError:
            return default
