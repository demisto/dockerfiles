# Script Sentinel - XSIAM Docker Image

Production-grade malware analysis for PowerShell, Bash, and JavaScript scripts in XSIAM with full ML integration.

## Overview

Script Sentinel is a security-focused script analyzer that provides:
- Multi-language support (PowerShell, Bash, JavaScript, VBScript)
- **6-scorer verdict system with ML integration**
- YARA pattern matching (custom + public rules)
- Embedded script extraction (from .sct, .html, .xml files)
- MITRE ATT&CK mapping
- IOC extraction
- Detailed threat intelligence output

## Architecture

### 6-Scorer Verdict System

1. **Severity Scorer (30%)** - Analyzes dangerous API calls and operations
2. **Co-occurrence Scorer (20%)** - Detects suspicious pattern combinations
3. **Kill Chain Scorer (15%)** - Maps to MITRE ATT&CK kill chain phases
4. **Content Intelligence Scorer (10%)** - AST-based semantic analysis
5. **YARA Scorer (15%)** - Pattern matching against rule database
6. **ML Scorer (10%)** - Hornet LightGBM models for malware detection

### ML Integration

**Hornet Models:**
- **JavaScript/VBScript:** 9,355 features, 0.5 threshold
- **PowerShell:** 26,143 features, 0.85 threshold

**Feature Extraction:**
- `hornet_genvector` - JS/VBS feature extraction
- `genpsvector` - PowerShell feature extraction

## Building the Docker Image

### Prerequisites

- Poetry installed
- Docker Desktop
- Access to `demisto/dockerfiles` repository

### Build Steps

1. **Navigate to image directory:**
   ```bash
   cd docker/script-sentinel
   ```

2. **Generate dependencies:**
   ```bash
   poetry lock
   poetry export -f requirements.txt --output requirements.txt --without-hashes
   ```

3. **Build locally (from dockerfiles root):**
   ```bash
   DOCKER_ORG=mytest \
   DOCKER_BUILD_PLATFORMS=linux/amd64 \
   DOCKER_INCLUDE_GREP=/script-sentinel$ \
   DOCKERHUB_USER=<your-username> \
   docker/build_docker.sh
   ```

4. **Test locally:**
   ```bash
   docker run --rm -it mytest/script-sentinel:1.0.0.<timestamp> /bin/bash
   python3 verify.py
   ```

5. **Create PR:**
   - Push changes to `demisto/dockerfiles`
   - CI will build and push to `devdemisto/script-sentinel:1.0.0.<build>`

## Deploying to XSIAM

### Prerequisites

- Demisto SDK installed: `pip install demisto-sdk`
- Access to `demisto/content` repository
- Docker image tag from previous step

### Deployment Steps

1. **Navigate to script directory:**
   ```bash
   cd content/Packs/CommonScripts/Scripts/ScriptSentinel
   ```

2. **Update `ScriptSentinel.yml` with Docker image:**
   ```yaml
   dockerimage: devdemisto/script-sentinel:1.0.0.<build_number>
   ```

3. **Package the script:**
   ```bash
   demisto-sdk unify
   ```
   This generates `script-ScriptSentinel.yml`

4. **Upload to XSIAM:**
   - Login to test environment (res1/res2)
   - Navigate: **Incident Response → Automation → scripts**
   - Upload `script-ScriptSentinel.yml`
   - Verify Docker image is recognized

## Technical Details

### Base Image

**Ubuntu 24.04** - Required for ML binary compatibility

### ML Dependencies

- **libssl1.1** - Required by hornet_genvector
- **libre2-5** - RE2 v5 ABI for pattern matching
- **libboost-locale 1.71.0** - Boost libraries

### Python Dependencies

- **ML:** numpy, lightgbm
- **Core:** tree-sitter, PyYAML, rich
- **Security:** yara-python
- **Optional:** google-generativeai (LLM features)

### Multi-Stage Build

1. **Builder stage:** Installs all dependencies and compiles extensions
2. **Runtime stage:** Minimal image with only runtime dependencies

**Image Size:** ~400 MB (includes ML models and binaries)

## Files in This Directory

- `Dockerfile` - Ubuntu 24.04 multi-stage build with ML
- `pyproject.toml` - Poetry dependency management
- `requirements.txt` - Generated from Poetry (do not edit manually)
- `build.conf` - Version configuration
- `verify.py` - Comprehensive verification script
- `README.md` - This file

## Version Management

Version is managed in `build.conf`:
```
version=1.0.0
```

The build system appends a timestamp/build number automatically.

## Performance

### Execution Time

- Small scripts (<1KB): 1-2 seconds
- Medium scripts (1-10KB): 2-5 seconds
- Large scripts (>10KB): 5-10 seconds

### ML Scoring Overhead

- Feature extraction: ~500ms
- Model inference: ~100ms
- Total ML overhead: ~600ms per script

## Comparison with Standalone Docker

Both images are **identical** - same codebase, same features, same ML models.

**Standalone Docker (`Dockerfile` in root):**
- For local deployment, CI/CD pipelines
- Same Ubuntu 24.04 base
- Same 6-scorer system with ML

**XSIAM Docker (`xsiam/demisto-pr-files/Dockerfile`):**
- For XSIAM integration
- Same Ubuntu 24.04 base
- Same 6-scorer system with ML
- Includes XSIAM wrapper integration

## Environment Variables

### Required

None - all configuration is baked into the Docker image.

### Optional

| Variable | Default | Purpose |
|----------|---------|---------|
| `ML_MODELS_DIR` | `/app/ml_models` | ML models directory |
| `TMPDIR` | `/app/temp` | Temporary files directory |
| `PYTHONPATH` | `/app` | Python module search path |

## Troubleshooting

### Build Issues

**Problem:** ML binaries not executable
```bash
# Solution: Check permissions in Dockerfile
RUN chmod +x /app/ml_models/hornet_genvector /app/ml_models/powershell/genpsvector
```

**Problem:** Missing libssl1.1
```bash
# Solution: Ensure .deb package is copied
COPY ml_models/libssl1.1_1.1.1f-1ubuntu2_amd64.deb /tmp/
```

### Runtime Issues

**Problem:** ML scoring fails
```bash
# Check binary compatibility
ldd /app/ml_models/hornet_genvector
ldd /app/ml_models/powershell/genpsvector
```

**Problem:** YARA rules not loading
```bash
# Ensure rules directory is copied
COPY --chown=sentinel:sentinel rules/ ./rules/
```

## Support

For issues or questions:
- **Internal:** Contact XDR Research team
- **Slack:** #xdr-research
- **Email:** aperetz@paloaltonetworks.com

## Resources

- **Demisto Dockerfiles:** https://github.com/demisto/dockerfiles
- **Demisto Content:** https://github.com/demisto/content
- **XSOAR Docs:** https://xsoar.pan.dev/docs/integrations/docker
- **Demisto SDK:** https://github.com/demisto/demisto-sdk