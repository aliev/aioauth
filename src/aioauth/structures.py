from collections import UserDict


class CaseInsensitiveDict(UserDict):
    """A case-insensitive ``dict``-like object."""

    def __setitem__(self, key, value):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())
