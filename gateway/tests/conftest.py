"""Pytest configuration: ensure the tests directory is on sys.path so the
adjacent `trust_helpers` module is importable from test files.
"""

import os
import sys

HERE = os.path.dirname(__file__)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
