"""Pytest bootstrap: make the repository root importable without installing.

pytest imports this conftest and puts its directory on ``sys.path``, so the
``pdfid`` package living next to it is importable from the test suite.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
