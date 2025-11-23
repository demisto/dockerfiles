#!/usr/bin/env python3
"""
Verify Script Sentinel Docker image
"""

# Verify core dependencies
import tree_sitter
import yaml
import rich
import dotenv

# Verify sentinel modules can be imported
from sentinel.analyzer import ScriptAnalyzer
from sentinel.extractor import ScriptExtractor

# Verify XSIAM wrapper
import xsiam_wrapper

print("All is good. Script Sentinel modules imported successfully")