import logging

__version__ = "2.0.0"

logging.getLogger("aioauth").addHandler(logging.NullHandler())
