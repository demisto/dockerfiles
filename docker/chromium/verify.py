from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, InvalidArgumentException
from PyPDF2 import PdfFileReader
from pdf2image import convert_from_path
import numpy as np
from PIL import Image
import sys
import base64
import subprocess

# verify the google-chrome and chromedriver have the same version (exluding patch level)
chrome_version = subprocess.check_output(["google-chrome", "--version"], text=True).split()[2]
driver_version = subprocess.check_output(["/usr/bin/chromedriver", "--version"], text=True).split()[1]

print(f'Comparing full versions: {chrome_version} to: {driver_version}')
chrome_version_arr = chrome_version.split('.')[:3]
driver_version_arr = driver_version.split('.')[:3]
print(f'Comparing  versions without patch: {chrome_version_arr} to: {driver_version_arr}')
assert chrome_version_arr == driver_version_arr

print('All is good!!!')
