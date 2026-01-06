# sentinel/patterns/__init__.py

"""
Pattern matching system for Script Sentinel.

This module provides a plugin-based pattern matching architecture for detecting
suspicious patterns in scripts across multiple languages (PowerShell, Bash, JavaScript).
"""

from .models import Pattern, PatternMatch
from .registry import PatternRegistry
from .loader import PatternLoader

__all__ = [
    'Pattern',
    'PatternMatch',
    'PatternRegistry',
    'PatternLoader',
]