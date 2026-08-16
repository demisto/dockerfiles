import os

# XSUP-72883: run the FIPS self-test on import; a broken cv2 wheel fails the build.
os.environ["OPENSSL_FORCE_FIPS_MODE"] = "1"

import cv2

print(f"opencv verify OK (cv2 {cv2.__version__})")
