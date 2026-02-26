# ML Models for Script Sentinel

This directory contains the Hornet machine learning models for malware detection.

## Structure

```
ml_models/
├── js/                      # JavaScript model
│   ├── model.txt           # LightGBM model (9,355 features)
│   ├── sample_fv.bin       # Sample feature vector
│   └── Readme.txt          # Model documentation
├── vbs/                     # VBScript model
│   ├── model.txt           # LightGBM model (707 features)
│   ├── sample_fv.bin       # Sample feature vector
│   └── Readme.txt          # Model documentation
├── powershell/              # PowerShell model
│   ├── model.txt           # LightGBM model (26,143 features)
│   ├── model.bin           # Proprietary format
│   ├── sample_fv.bin       # Sample feature vector
│   ├── genpsvector         # Feature extractor binary
│   ├── psscanner           # End-to-end scanner binary
│   └── Readme.txt          # Model documentation
├── hornet_genvector        # JS/VBS feature extractor (optional)
├── scanner.py              # Standalone scanner utility
├── generate_prediction.py  # Batch prediction utility
└── requirements.txt        # Python dependencies
```

## Models

| Model | File Types | Features | Threshold | Status |
|-------|-----------|----------|-----------|--------|
| **JavaScript** | .js, .jse | 9,355 | 0.5 | ✅ Model ready |
| **VBScript** | .vbs, .vbe | 707 | 0.9 | ✅ Model ready |
| **PowerShell** | .ps1 | 26,143 | 0.85 | ✅ Fully functional |

## Usage

### Test Models
```bash
python3 generate_prediction.py
```

### Scan Feature Vector
```bash
python3 scanner.py powershell ./powershell/sample_fv.bin
```

## Integration with Script Sentinel

These models are integrated into Script Sentinel via the `HornetMLScorer` class
in `sentinel/scorers/hornet_scorer.py`.

## Requirements

- Python 3.7+
- numpy >= 1.19.0
- lightgbm >= 3.0.0

Install with:
```bash
pip install -r requirements.txt
```
