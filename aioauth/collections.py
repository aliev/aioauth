"""
Collections that are used throughout the project.
```python
from aioauth import collections
```
"""

from collections import UserDict
from typing import Any


class HTTPHeaderDict(UserDict):
    """
    A dict-like container for storing HTTP headers with case-insensitive keys.

    Args:
        headers (Optional[Mapping[str, str]]):
            An iterable of field-value pairs. Must not contain duplicate field
            names (case-insensitively).
        **kwargs:
            Additional key-value pairs passed to `dict.update`.

    Example:
        ```python
        from aioauth.collections import HTTPHeaderDict
        d = HTTPHeaderDict({"hello": "world"})
        print(d['hello'])  # >>> 'world'
        print(d['Hello'])  # >>> 'world'
        print(d['hElLo'])  # >>> 'world'
        ```
    """

    def __init__(self, headers=None, **kwargs):
        """Initialize the case-insensitive dictionary."""
        super().__init__(headers, **kwargs)
        self.data = {k.lower(): v for k, v in self.data.items()}

    def __setitem__(self, key: str, value: str):
        """Set a key-value pair with case-insensitive key."""
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key: str):
        """Retrieve a value by case-insensitive key."""
        return super().__getitem__(key.lower())

    def __delitem__(self, key: str):
        """Delete a key-value pair using a case-insensitive key."""
        return super().__delitem__(key.lower())

    def get(self, key: str, default: Any = None):
        """
        Return the value for key if key is in the dictionary, else default.

        Args:
            key (str): The key to search for (case-insensitive).
            default (Any, optional): The value to return if key is not found.

        Returns:
            Any: The value associated with the key, or default if not found.
        """
        try:
            return self[key]
        except KeyError:
            return default
