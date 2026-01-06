# Script Sentinel Docker Image for XSIAM
# Production-grade with full ML integration (6-scorer system)
# Using Ubuntu 24.04 (ml_models/hornet_genvector is compiled for 24.04)

# Stage 1: Builder
FROM ubuntu:24.04 AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Copy libssl1.1 package for hornet_genvector compatibility
COPY ml_models/libssl1.1_1.1.1f-1ubuntu2_amd64.deb /tmp/

# Install build dependencies and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3.12 \
    python3-pip \
    python3-dev \
    python3-venv \
    # Build tools
    gcc \
    g++ \
    build-essential \
    # Hornet runtime dependencies (Ubuntu 24.04)
    libre2-10 \
    libssl3 \
    libboost-locale1.83.0 \
    # Download tool for libre2-5
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install additional dependencies for hornet_genvector binary compatibility
RUN cd /tmp \
    # Install libssl1.1 from .deb package (not in Ubuntu 24.04 repos)
    && dpkg -i /tmp/libssl1.1_1.1.1f-1ubuntu2_amd64.deb \
    && rm /tmp/libssl1.1_1.1.1f-1ubuntu2_amd64.deb \
    # Download and install libre2-5 from Ubuntu 20.04 (hornet_genvector requires RE2 v5 ABI)
    && wget -q http://archive.ubuntu.com/ubuntu/pool/main/r/re2/libre2-5_20200101+dfsg-1build1_amd64.deb \
    && dpkg -i libre2-5_20200101+dfsg-1build1_amd64.deb \
    && rm libre2-5_20200101+dfsg-1build1_amd64.deb \
    # Create symbolic links for version compatibility
    && cd /usr/lib/x86_64-linux-gnu \
    && ln -sf libre2.so.5.0.0 libre2.so.5 \
    && ln -s libboost_locale.so.1.83.0 libboost_locale.so.1.71.0

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages \
    # ML dependencies
    numpy>=1.19.0 \
    lightgbm>=3.0.0 \
    # Script-Sentinel core dependencies
    tree-sitter>=0.25.2 \
    tree-sitter-language-pack \
    pyyaml>=6.0.2 \
    python-dotenv>=1.0.1 \
    rich>=13.7.0 \
    yara-python>=4.3.0

# Stage 2: Runtime
FROM ubuntu:24.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set metadata
LABEL maintainer="aperetz@paloaltonetworks.com"
LABEL description="Script Sentinel - XSIAM malware detection with ML integration"
LABEL version="1.0.0"
LABEL com.demisto.image.type="python"
LABEL com.demisto.image.category="malware-analysis"

# Set working directory
WORKDIR /app

# Copy runtime dependencies from builder
COPY --from=builder /usr/lib/x86_64-linux-gnu/libre2.so.5* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssl.so.1.1* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libboost_locale.so.1.71.0 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libboost_locale.so.1.83.0 /usr/lib/x86_64-linux-gnu/

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3-pip \
    libssl3 \
    libre2-10 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    # Create python symlink for CI compatibility
    && ln -s /usr/bin/python3 /usr/bin/python

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages

# Create non-root user for security
# Use --non-unique flag in case UID 1000 already exists in base image
RUN useradd -m -u 1000 --non-unique sentinel 2>/dev/null || \
    useradd -m sentinel && \
    chown -R sentinel:sentinel /app

# Copy application code
# Note: The Demisto build script will copy these from the main repo
COPY --chown=sentinel:sentinel sentinel/ ./sentinel/
COPY --chown=sentinel:sentinel config/ ./config/
COPY --chown=sentinel:sentinel rules/ ./rules/
COPY --chown=sentinel:sentinel ml_models/ ./ml_models/

# Copy XSIAM wrapper (renamed from ScriptSentinel.py during build)
COPY --chown=sentinel:sentinel xsiam_wrapper.py ./

# Copy verification script
COPY --chown=sentinel:sentinel verify.py ./

# Create directories for temp files with proper permissions
RUN mkdir -p /app/temp && \
    chown -R sentinel:sentinel /app/temp

# Make ML binaries executable
RUN chmod +x /app/ml_models/hornet_genvector /app/ml_models/powershell/genpsvector 2>/dev/null || true

# Switch to non-root user
# USER sentinel

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV ML_MODELS_DIR=/app/ml_models
ENV TMPDIR=/app/temp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import sentinel; import xsiam_wrapper; print('healthy')" || exit 1

# No ENTRYPOINT - let Demisto verification run commands directly
# The XSIAM integration will call xsiam_wrapper.py explicitly