# XSUP-72883: importing cv2/pyzbar runs the OpenSSL FIPS self-test at build time,
# so a wheel with a broken bundled OpenSSL fails the build here (not on a host).
import cv2
import pyzbar.pyzbar
import wurlitzer

# Explicit references so static analysis sees the imports as used.
_MODULES = (cv2, pyzbar.pyzbar, wurlitzer)

print("qrcode verify OK")
