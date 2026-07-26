import os
import sys

# XSUP-72883: side-effect imports. Loading cv2/pyzbar runs the OpenSSL FIPS
# self-test at build time, so a broken fips.so fails the build here.
import pyzbar.pyzbar  # noqa: F401
import cv2  # noqa: F401
import wurlitzer  # noqa: F401

# XSUP-72883: fail the build if fips.so is missing.
if not os.path.exists("/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so"):
    print("XSUP-72883 guard failed: fips.so is missing; FIPS hosts will crash.")
    sys.exit(1)

print("qrcode verify OK")
