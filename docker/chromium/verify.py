from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, InvalidArgumentException
from PyPDF2 import PdfFileReader
import pdf2image
import numpy as np
from PIL import Image
import sys
import base64
import subprocess
import pychrome
from psutil import Process

# verify the google-chrome and chromedriver have the same version (exluding patch level)
chrome_version = subprocess.check_output(["google-chrome", "--version"], text=True).split()[2]
driver_version = subprocess.check_output(["/usr/bin/chromedriver", "--version"], text=True).split()[1]

print(f'Comparing full versions: {chrome_version} to: {driver_version}')
chrome_version_arr = chrome_version.split('.')[:3]
driver_version_arr = driver_version.split('.')[:3]
print(f'Comparing  versions without patch: {chrome_version_arr} to: {driver_version_arr}')
assert chrome_version_arr == driver_version_arr

print(f'Using pychrome version {pychrome.__version__}')

print(f'Using poppler version: {pdf2image.pdf2image._get_poppler_version("pdftocairo")}')
poppler_version = pdf2image.pdf2image._get_poppler_version("pdftoppm")
assert poppler_version[0] > 20

print('All is good!!!')
