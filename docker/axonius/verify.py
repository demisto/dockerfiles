"""Verification script for the axonius image.

The axonius-api-client package (through its latest release) still references a
handful of APIs that were removed in newer releases of its dependencies:

  * urllib3 >= 2.0 removed ``HTTPSConnectionPool.ResponseCls``
  * pyOpenSSL >= 24.0 removed ``OpenSSL.crypto.X509Req``

The image intentionally ships the newer, patched versions of those
dependencies, so we install small backwards-compatibility shims here before
importing the client. The shims re-expose the removed names by aliasing them to
their modern equivalents, allowing the client to import and operate normally.
"""

from urllib3 import connectionpool
from urllib3.response import HTTPResponse

if not hasattr(connectionpool.HTTPSConnectionPool, "ResponseCls"):
    connectionpool.HTTPSConnectionPool.ResponseCls = HTTPResponse
    connectionpool.HTTPConnectionPool.ResponseCls = HTTPResponse

import OpenSSL.crypto as _openssl_crypto

if not hasattr(_openssl_crypto, "X509Req"):
    _openssl_crypto.X509Req = _openssl_crypto.X509

import axonius_api_client as axonapi

print(axonapi)
