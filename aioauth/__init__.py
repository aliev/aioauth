import logging

__version__ = "2.0.1"

logging.getLogger("aioauth").addHandler(logging.NullHandler())
