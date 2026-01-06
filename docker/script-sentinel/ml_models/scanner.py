#!/usr/bin/env python3
"""
Standalone Hornet Malware Scanner
Usage: python scanner.py <model_type> <feature_vector.bin>
Example: python scanner.py JS ./JS/sample_fv.bin
"""

import sys
import struct
import numpy as np
import lightgbm as lgbm

MODELS = {
    "JS": {"features": 9355, "threshold": 0.5, "model": "JS/model.txt"},
    "VBS": {"features": 707, "threshold": 0.9, "model": "VBS/model.txt"},
    "PS": {"features": 26143, "threshold": 0.85, "model": "PS/model.txt"}
}

def load_binary_fv(filepath, num_features):
    """Load and convert binary feature vector to dense numpy array"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if len(data) == 0:
        raise ValueError("Empty feature vector file")
    
    fv = np.zeros(num_features)
    feature_size = 16  # 8 bytes (uint64) + 8 bytes (double)
    
    if len(data) % feature_size != 0:
        raise ValueError(f"Invalid file size: {len(data)} bytes (expected multiple of 16)")
    
    num_nonzero = len(data) // feature_size
    for i in range(num_nonzero):
        idx, val = struct.unpack("Qd", data[i*16:(i+1)*16])
        if idx >= num_features:
            raise ValueError(f"Feature index {idx} exceeds model size {num_features}")
        fv[idx] = val
    
    return fv

def scan(model_type, fv_path):
    """Scan a feature vector file and return prediction results"""
    model_type = model_type.upper()
    
    if model_type not in MODELS:
        raise ValueError(f"Unknown model type: {model_type}. Use JS, VBS, or PS")
    
    config = MODELS[model_type]
    
    print(f"Loading {model_type} model from {config['model']}...")
    booster = lgbm.Booster(model_file=config["model"])
    
    print(f"Reading feature vector from {fv_path}...")
    fv = load_binary_fv(fv_path, config["features"])
    
    print(f"Generating prediction...")
    score = booster.predict(fv.reshape(1, -1))[0]
    
    is_malicious = score >= config["threshold"]
    
    return {
        "model": model_type,
        "score": score,
        "threshold": config["threshold"],
        "verdict": "MALICIOUS" if is_malicious else "BENIGN",
        "features": config["features"],
        "nonzero_features": np.count_nonzero(fv)
    }

def main():
    if len(sys.argv) != 3:
        print("Standalone Hornet Malware Scanner")
        print("=" * 60)
        print("Usage: python scanner.py <MODEL_TYPE> <FEATURE_VECTOR_FILE>")
        print()
        print("MODEL_TYPE: JS, VBS, or PS")
        print("FEATURE_VECTOR_FILE: Path to binary feature vector (.bin)")
        print()
        print("Examples:")
        print("  python scanner.py JS ./JS/sample_fv.bin")
        print("  python scanner.py VBS ./VBS/sample_fv.bin")
        print("  python scanner.py PS ./PS/sample_fv.bin")
        print()
        print("Model Thresholds:")
        for model, config in MODELS.items():
            print(f"  {model}: {config['threshold']} ({config['features']} features)")
        sys.exit(1)
    
    model_type = sys.argv[1]
    fv_path = sys.argv[2]
    
    try:
        result = scan(model_type, fv_path)
        
        print()
        print("=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Model:              {result['model']}")
        print(f"Feature Vector:     {fv_path}")
        print(f"Total Features:     {result['features']}")
        print(f"Non-zero Features:  {result['nonzero_features']}")
        print(f"Prediction Score:   {result['score']:.6f}")
        print(f"Detection Threshold: {result['threshold']}")
        print(f"Verdict:            {result['verdict']}")
        print("=" * 60)
        
        # Exit code: 0 for benign, 1 for malicious
        sys.exit(1 if result['verdict'] == "MALICIOUS" else 0)
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found - {e}")
        sys.exit(2)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()