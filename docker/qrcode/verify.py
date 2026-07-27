import os

# XSUP-72883: run the FIPS self-test on import; a broken cv2 wheel fails the build.
os.environ["OPENSSL_FORCE_FIPS_MODE"] = "1"

from pyzbar.pyzbar import decode
import cv2
from wurlitzer import pipes

print("qrcode verify OK")
