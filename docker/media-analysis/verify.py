import shutil

import cv2
import easyocr
import reportlab
import playwright
import yt_dlp

from playwright.sync_api import sync_playwright

print("Checking imports...")

assert cv2 is not None
assert easyocr is not None
assert reportlab is not None
assert playwright is not None
assert yt_dlp is not None

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

print("Checking ffmpeg...")

assert shutil.which("ffmpeg") is not None

print("ffmpeg OK")

print("Checking yt-dlp...")

with yt_dlp.YoutubeDL({"quiet": True}) as ydl:
    pass

print("yt-dlp OK")

print("Verification successful")