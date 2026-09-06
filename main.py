#!/usr/bin/env python3
"""
main.py
Entry point for the SSH brute-force detector.

    python main.py /var/log/auth.log --threshold 5 --window 10 --format json
"""

import sys

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())