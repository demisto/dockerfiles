import cv2
import easyocr
import pyppeteer
import reportlab

from pyppeteer.chromium_downloader import check_chromium


print("Checking imports...")

assert cv2 is not None
assert easyocr is not None
assert pyppeteer is not None
assert reportlab is not None

print("Imports OK")


print("Checking Chromium...")

assert check_chromium(), "Chromium was not downloaded"

print("Chromium OK")


print("Checking EasyOCR model...")

reader = easyocr.Reader(
    ['en', 'es'],
    gpu=False
)

print("EasyOCR OK")

print("Verification successful")