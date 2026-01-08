#!/usr/bin/env python3
"""
Verify Script Sentinel Docker image for XSIAM deployment
Tests that all required dependencies are installed and importable
Includes ML and YARA verification

Version: 1.0.1 - Added LD_LIBRARY_PATH verification for ML binary compatibility
Last Updated: 2026-01-08
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
    
    # Main directories
    directories = [
        "/app/sentinel",
        "/app/config",
        "/app/rules",
        "/app/ml_models",
        "/app/temp",
        "/app/data",
        # Sentinel subdirectories
        "/app/sentinel/scorers",
        "/app/sentinel/reporters",
        "/app/sentinel/utils",
        # Rules subdirectories
        "/app/rules/public",
        "/app/rules/staging",
        "/app/rules/templates",
        # ML models subdirectories
        "/app/ml_models/js",
        "/app/ml_models/vbs",
        "/app/ml_models/powershell",
        # Rules language subdirectories
        "/app/rules/public/bash",
        "/app/rules/public/javascript",
        "/app/rules/public/powershell",
        "/app/rules/public/python",
        "/app/rules/public/webshells",
        "/app/rules/custom/bash",
        "/app/rules/custom/javascript",
        "/app/rules/custom/powershell"
    ]
    
    for directory in directories:
        if os.path.isdir(directory):
            print(f"✓ {directory} exists")
        else:
            errors.append(f"✗ {directory} not found")
    
    return errors

def verify_environment():
    """Verify required environment variables are set"""
    errors = []
    
    # Check LD_LIBRARY_PATH for ML binary compatibility
    ld_library_path = os.environ.get('LD_LIBRARY_PATH', '')
    if '/usr/lib/x86_64-linux-gnu' in ld_library_path and '/app/ml_models' in ld_library_path:
        print(f"✓ LD_LIBRARY_PATH is set correctly: {ld_library_path}")
    else:
        errors.append(f"✗ LD_LIBRARY_PATH not set correctly. Current: {ld_library_path}")
    
    # Check ML_MODELS_DIR
    ml_models_dir = os.environ.get('ML_MODELS_DIR', '')
    if ml_models_dir == '/app/ml_models':
        print(f"✓ ML_MODELS_DIR is set correctly: {ml_models_dir}")
    else:
        errors.append(f"✗ ML_MODELS_DIR not set correctly. Current: {ml_models_dir}")
    
    # Check PYTHONPATH
    pythonpath = os.environ.get('PYTHONPATH', '')
    if '/app' in pythonpath:
        print(f"✓ PYTHONPATH is set correctly: {pythonpath}")
    else:
        errors.append(f"✗ PYTHONPATH not set correctly. Current: {pythonpath}")
    
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
    
    print("Checking environment variables...")
    env_errors = verify_environment()
    print()
    
    all_errors = import_errors + binary_errors + directory_errors + env_errors
    
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