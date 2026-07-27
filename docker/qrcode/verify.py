from pyzbar.pyzbar import decode
import cv2

# XSUP-72883: importing/using cv2 and pyzbar loads their bundled OpenSSL and runs
# the FIPS self-test, so a broken wheel fails the build here, not on a FIPS host.
assert callable(decode)
assert callable(cv2.QRCodeDetector)

print("qrcode verify OK")
