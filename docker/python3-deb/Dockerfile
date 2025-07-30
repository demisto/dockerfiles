# Last modified: 2025-07-30T14:49:10+03:00
FROM python:3.12.11-slim-bookworm

RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Upgrade using backports
RUN apt-get update && apt-get -t bookworm-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Relevant for tldextract
COPY public_list.dat /var/public_list.dat

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \ 
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/* \
&& pip install --upgrade setuptools

# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation and ignoring SSL legacy renegotiation errors
# We add to the openssl_init section after the last element "providers = provider_sect"
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org && \
echo 'ssl_conf = ssl_sect\n\
[ssl_sect]\n\
system_default = system_default_sect\n\
\n\
[system_default_sect]\n\
Options = UnsafeLegacyRenegotiation,IgnoreUnexpectedEOF\n\
CipherString = DEFAULT@SECLEVEL=0\n\
MinProtocol = TLSv1.2\n' > /tmp/ssl.cnf \
&& sed -i '/providers = provider_sect/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& grep -C 10 'Options = UnsafeLegacyRenegotiation,IgnoreUnexpectedEOF' /etc/ssl/openssl.cnf

# Create a Python script to configure SSL settings to make OpenSSL 3 behave more like OpenSSL 1.1
RUN echo '#!/usr/bin/env python3\n\
import ssl\n\
import os\n\
\n\
# Create a file that will be imported by Python applications to configure SSL\n\
with open("/usr/local/lib/python3.12/ssl_backcompat.py", "w") as f:\n\
    f.write("""\n\
# This module configures SSL settings to make OpenSSL 3 behave more like OpenSSL 1.1\n\
import ssl\n\
import os\n\
\n\
def patch_ssl():\n\
    """Configure SSL settings to make OpenSSL 3 behave more like OpenSSL 1.1"""\n\
    # Create a default context with less restrictive settings\n\
    default_ctx = ssl.create_default_context()\n\
    \n\
    # Set security level to 1 (equivalent to OpenSSL 1.1.1 default)\n\
    default_ctx.set_ciphers("DEFAULT@SECLEVEL=1")\n\
    \n\
    # Enable legacy renegotiation support\n\
    default_ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT\n\
    \n\
    # Add all workarounds for various SSL implementation bugs\n\
    default_ctx.options |= ssl.OP_ALL\n\
    \n\
    # Allow legacy insecure renegotiation\n\
    if hasattr(ssl, "OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION"):\n\
        default_ctx.options |= ssl.OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION\n\
    \n\
    # Set minimum TLS version to be compatible with OpenSSL 1.1\n\
    if hasattr(ssl, "TLSVersion"):\n\
        default_ctx.minimum_version = ssl.TLSVersion.TLSv1\n\
        # Don\'t restrict maximum version\n\
        default_ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED\n\
    \n\
    # Set as the default context for all future SSL connections\n\
    ssl._create_default_https_context = lambda: default_ctx\n\
    \n\
    # Also set environment variables that some libraries might use\n\
    os.environ["OPENSSL_CONF"] = "/etc/ssl/openssl.cnf"\n\
    os.environ["OPENSSL_ALLOW_PROXY_CERTS"] = "1"\n\
    os.environ["OPENSSL_ALLOW_UNSAFE_LEGACY_RENEGOTIATION"] = "1"\n\
\n\
# Apply the patch by default when this module is imported\n\
patch_ssl()\n\
""")\n\
\n\
# Create a sitecustomize.py file to auto-import our SSL settings\n\
with open("/usr/local/lib/python3.12/sitecustomize.py", "w") as f:\n\
    f.write("""\n\
# Auto-import SSL backcompat settings\n\
try:\n\
    import ssl_backcompat\n\
except ImportError:\n\
    pass\n\
""")\n\
' > /tmp/configure_ssl.py && python3 /tmp/configure_ssl.py && rm /tmp/configure_ssl.py

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
