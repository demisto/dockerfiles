#!/usr/bin/env python3
"""
Verify Script Sentinel Docker image for XSIAM deployment
Tests that all required dependencies are installed and importable
Includes ML and YARA verification
"""

import sys
import os

def verify_imports():
    """Verify all required modules can be imported"""
    errors = []
    
    # Core dependencies
    try:
        import tree_sitter
        print("✓ tree_sitter imported successfully")
    except ImportError as e:
        errors.append(f"✗ tree_sitter import failed: {e}")
    
    try:
        import yaml
        print("✓ yaml imported successfully")
    except ImportError as e:
        errors.append(f"✗ yaml import failed: {e}")
    
    try:
        import rich
        print("✓ rich imported successfully")
    except ImportError as e:
        errors.append(f"✗ rich import failed: {e}")
    
    # ML dependencies
    try:
        import numpy
        print("✓ numpy imported successfully")
    except ImportError as e:
        errors.append(f"✗ numpy import failed: {e}")
    
    try:
        import lightgbm
        print("✓ lightgbm imported successfully")
    except ImportError as e:
        errors.append(f"✗ lightgbm import failed: {e}")
    
    # YARA
    try:
        import yara
        print("✓ yara-python imported successfully")
    except ImportError as e:
        errors.append(f"✗ yara-python import failed: {e}")
    
    # Sentinel modules
    try:
        from sentinel.analyzer import ScriptAnalyzer
        print("✓ sentinel.analyzer imported successfully")
    except ImportError as e:
        errors.append(f"✗ sentinel.analyzer import failed: {e}")
    
    try:
        from sentinel.extractor import ScriptExtractor
        print("✓ sentinel.extractor imported successfully")
    except ImportError as e:
        errors.append(f"✗ sentinel.extractor import failed: {e}")
    
    try:
        from sentinel.models import AnalysisResult
        print("✓ sentinel.models imported successfully")
    except ImportError as e:
        errors.append(f"✗ sentinel.models import failed: {e}")
    
    try:
        from sentinel.scorers.ml import MLScorer
        print("✓ sentinel.scorers.ml imported successfully")
    except ImportError as e:
        errors.append(f"✗ sentinel.scorers.ml import failed: {e}")
    
    try:
        from sentinel.yara_engine import YaraEngine
        print("✓ sentinel.yara_engine imported successfully")
    except ImportError as e:
        errors.append(f"✗ sentinel.yara_engine import failed: {e}")
    
    # XSIAM wrapper
    try:
        import xsiam_wrapper
        print("✓ xsiam_wrapper imported successfully")
    except ImportError as e:
        errors.append(f"✗ xsiam_wrapper import failed: {e}")
    
    # Optional: Google AI (may not be configured)
    try:
        import google.generativeai
        print("✓ google.generativeai imported successfully (optional)")
    except ImportError:
        print("⚠ google.generativeai not available (optional)")
    
    return errors

def verify_ml_binaries():
    """Verify ML binaries are present and executable"""
    errors = []
    
    # Check hornet_genvector
    hornet_path = "/app/ml_models/hornet_genvector"
    if os.path.exists(hornet_path):
        if os.access(hornet_path, os.X_OK):
            print(f"✓ {hornet_path} exists and is executable")
        else:
            errors.append(f"✗ {hornet_path} exists but is not executable")
    else:
        errors.append(f"✗ {hornet_path} not found")
    
    # Check genpsvector
    genpsvector_path = "/app/ml_models/powershell/genpsvector"
    if os.path.exists(genpsvector_path):
        if os.access(genpsvector_path, os.X_OK):
            print(f"✓ {genpsvector_path} exists and is executable")
        else:
            errors.append(f"✗ {genpsvector_path} exists but is not executable")
    else:
        errors.append(f"✗ {genpsvector_path} not found")
    
    # Check ML models
    models = [
        "/app/ml_models/js/model.txt",
        "/app/ml_models/vbs/model.txt",
        "/app/ml_models/powershell/model.bin"
    ]
    
    for model_path in models:
        if os.path.exists(model_path):
            print(f"✓ {model_path} exists")
        else:
            errors.append(f"✗ {model_path} not found")
    
    return errors

def verify_directories():
    """Verify required directories exist"""
    errors = []
    
    directories = [
        "/app/sentinel",
        "/app/config",
        "/app/rules",
        "/app/ml_models",
        "/app/temp"
    ]
    
    for directory in directories:
        if os.path.isdir(directory):
            print(f"✓ {directory} exists")
        else:
            errors.append(f"✗ {directory} not found")
    
    return errors

def main():
    """Main verification function"""
    print("=" * 60)
    print("Script Sentinel Docker Image Verification")
    print("XSIAM Deployment - Full ML Integration")
    print("=" * 60)
    print()
    
    print("Checking Python imports...")
    import_errors = verify_imports()
    print()
    
    print("Checking ML binaries...")
    binary_errors = verify_ml_binaries()
    print()
    
    print("Checking directories...")
    directory_errors = verify_directories()
    print()
    
    all_errors = import_errors + binary_errors + directory_errors
    
    print("=" * 60)
    
    if all_errors:
        print("VERIFICATION FAILED")
        print()
        for error in all_errors:
            print(error)
        sys.exit(1)
    else:
        print("✓ ALL CHECKS PASSED")
        print("Script Sentinel Docker image is ready for XSIAM deployment")
        print("Features: 6-scorer system with ML integration")
        sys.exit(0)

if __name__ == "__main__":
    main()