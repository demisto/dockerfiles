# Script Sentinel Docker Image for XSIAM
# Malware analysis for PowerShell, Bash, and JavaScript scripts

# Use official Demisto Python 3 base image (Alpine-based)
# Check latest version at: https://hub.docker.com/r/demisto/python3/tags
FROM demisto/python3:3.11.9.109876

# Metadata
LABEL maintainer="aperetz@paloaltonetwroks.com"
LABEL description="Script Sentinel - Malware analysis for PowerShell, Bash, and JavaScript"
LABEL version="1.0.0"
LABEL com.demisto.image.type="python"
LABEL com.demisto.image.category="malware-analysis"

# Set working directory
WORKDIR /app

# Create non-root user (if not already in base image)
# Demisto base images typically already have a user, but we ensure it exists
RUN addgroup -g 1000 -S sentinel 2>/dev/null || true && \
    adduser -u 1000 -S sentinel -G sentinel 2>/dev/null || true

# Copy requirements first for better caching
# Note: If using poetry, the build script will auto-generate requirements.txt
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY sentinel/ ./sentinel/
COPY xsiam_wrapper.py ./
COPY docker-entrypoint.sh ./

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

# Switch to non-root user
USER sentinel

# Set Python path
ENV PYTHONPATH=/app:$PYTHONPATH

# Health check (optional)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sentinel; import xsiam_wrapper" || exit 1

# Entrypoint
ENTRYPOINT ["./docker-entrypoint.sh"]

# Default command (can be overridden)
CMD ["--help"]