#!/usr/bin/env python3
"""
Allow running the scraper as a package: python -m trr_source_scraper

Delegates entirely to the main entry point in trr_scraper.py.
"""

import sys
from trr_scraper import main

sys.exit(main())
