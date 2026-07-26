import os
import sys

from pyzbar.pyzbar import decode  # noqa: F401
import cv2  # noqa: F401
from wurlitzer import pipes  # noqa: F401

# XSUP-72883: fail the build if the bundled FIPS provider is missing, otherwise
# cv2/pyzbar abort with "FATAL FIPS SELFTEST FAILURE" on FIPS-enabled hosts.
if not os.path.exists("/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so"):
    print("XSUP-72883 guard failed: fips.so is missing; FIPS hosts will crash.")
    sys.exit(1)

print("qrcode verify OK")
