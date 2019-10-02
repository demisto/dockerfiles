from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, InvalidArgumentException
from PyPDF2 import PdfFileReader
from pdf2image import convert_from_path
import numpy as np
from PIL import Image
import sys
import base64