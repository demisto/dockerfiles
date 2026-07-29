import cv2
import easyocr
import reportlab
import playwright

from playwright.sync_api import sync_playwright

print("Checking imports...")

assert cv2 is not None
assert easyocr is not None
assert reportlab is not None
assert playwright is not None

print("Imports OK")

print("Checking Chromium...")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("about:blank")
    browser.close()

print("Chromium OK")

print("Checking EasyOCR model...")

reader = easyocr.Reader(["en", "es"], gpu=False)

print("EasyOCR OK")

print("Verification successful")