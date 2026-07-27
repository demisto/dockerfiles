# XSUP-72883: side-effect imports; loading cv2/pyzbar runs the FIPS self-test at build.
import cv2  # noqa: F401
import pyzbar.pyzbar  # noqa: F401
import wurlitzer  # noqa: F401

print("qrcode verify OK")
