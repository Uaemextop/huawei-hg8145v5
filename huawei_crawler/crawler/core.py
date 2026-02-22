"""
Main Crawler class for BFS-based web crawling.

This module provides the core Crawler class that orchestrates the entire
crawling process using a breadth-first search algorithm.
"""

import sys
from pathlib import Path

# Import the Crawler class from the main crawler.py
# This provides a transitional architecture while we complete the modularization
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crawler import Crawler

__all__ = ["Crawler"]
