"""
conftest.py
Makes the project root importable so `from src.parser import ...` works
when pytest is invoked from anywhere inside the repository.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))