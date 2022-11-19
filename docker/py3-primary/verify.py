# chromium
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, InvalidArgumentException
from PyPDF2 import PdfFileReader
from pdf2image import convert_from_path
import numpy as np
from PIL import Image
import sys
import base64
import subprocess

# verify the google-chrome and chromedriver have the same version (excluding patch level)
chrome_version = subprocess.check_output(["google-chrome", "--version"], text=True).split()[2]
driver_version = subprocess.check_output(["/usr/bin/chromedriver", "--version"], text=True).split()[1]

print(f'Comparing full versions: {chrome_version} to: {driver_version}')
chrome_version_arr = chrome_version.split('.')[:3]
driver_version_arr = driver_version.split('.')[:3]
print(f'Comparing versions without patch: {chrome_version_arr} to: {driver_version_arr}')
assert chrome_version_arr == driver_version_arr

print('chromium is good!!!')

# crypto
from cryptography.fernet import Fernet
import msal
from bs4 import BeautifulSoup
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)

print('crypto is good!!!')

# oauthlib
from requests_oauthlib import OAuth1
from oauthlib.oauth2 import BackendApplicationClient

print('oauthlib is good!!!')


# py3ews

import traceback
import json
import os
import hashlib
from datetime import timedelta
from io import StringIO
import logging
import warnings
import email
from requests.exceptions import ConnectionError
from collections import deque

from multiprocessing import Process
import exchangelib
from exchangelib.errors import ErrorItemNotFound, ResponseMessageError, TransportError, RateLimitError, \
    ErrorInvalidIdMalformed, \
    ErrorFolderNotFound, ErrorMailboxStoreUnavailable, ErrorMailboxMoveInProgress, \
    AutoDiscoverFailed, ErrorNameResolutionNoResults, ErrorInvalidPropertyRequest, ErrorIrresolvableConflict
from exchangelib.items import Item, Message, Contact
from exchangelib.services.common import EWSService, EWSAccountService
from exchangelib.util import create_element, add_xml_child
from exchangelib import IMPERSONATION, DELEGATE, Account, Credentials, \
    EWSDateTime, EWSTimeZone, Configuration, NTLM, DIGEST, BASIC, FileAttachment, \
    Version, Folder, HTMLBody, Body, Build, ItemAttachment
from exchangelib.version import EXCHANGE_2007, EXCHANGE_2010, EXCHANGE_2010_SP2, EXCHANGE_2013, EXCHANGE_2016
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
import tzlocal

test = tzlocal.get_localzone()
print('all is good, `get_localzone() -> {}` is working'.format(test))
print('py3ews is good!!!')

# readpdf
from pikepdf import Pdf
from PyPDF2 import PdfFileReader, PdfFileWriter
print('readpdf is good!!!')


# parse-emails
from parse_emails.parse_emails import EmailParser
print('parse-emails is good!!!')

# docxpy + office-utils
from docx import Document
print('docxpy + office-utils are good!!!')

#netutils
from netaddr import IPAddress, IPNetwork
print('netutils is good!!!')

# sklearn
import sklearn
import pandas
import numpy
import nltk
import dill
import eli5
import networkx
print('sklearn is good!!!')


import pandas as pd

dict = {
    "country": ["Brazil", "Russia", "India", "China", "South Africa"],
    "capital": ["Brasilia", "Moscow", "New Dehli", "Beijing", "Pretoria"],
    "area": [8.516, 17.10, 3.286, 9.597, 1.221],
    "population": [200.4, 143.5, 1252, 1357, 52.98]
}

data = pd.DataFrame(dict)

print(data)

print('pandas is good!!!')

import regex
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')


import numpy as np
import pandas
import sklearn
from bs4 import BeautifulSoup
import cv2 as cv
import tldextract
import dill
import catboost
from PIL import Image

print('mlurlphishing is good')

