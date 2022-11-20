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


# tesseract
subprocess.check_output(["tesseract", "--version", "--list-langs"], text=True)

# crypto
from cryptography.fernet import Fernet
import msal
from bs4 import BeautifulSoup
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)

print('crypto is good!!!')


# readpdf
from pikepdf import Pdf
from PyPDF2 import PdfFileReader, PdfFileWriter
print('readpdf is good!!!')


# parse-emails
from parse_emails.parse_emails import EmailParser
print('parse-emails is good!!!')


# docxpy + office-utils
from docx import Document
# make sure libreoffice is installed
subprocess.check_output(["soffice", "--version"], text=True)
print('docxpy + office-utils are good!!!')


# sklearn
import sklearn
import pandas
import numpy
import nltk
import dill
import eli5
import networkx
print('sklearn is good!!!')

# pandas
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

# ippysocks-py3
import whois
print('ippysocks-py3 is good!!!')


# oauthlib
from requests_oauthlib import OAuth1
from oauthlib.oauth2 import BackendApplicationClient
print('oauthlib is good!!!')

# unzip
subprocess.check_output(["unrar", "--version"], text=True)
subprocess.check_output(["7z", "--version"], text=True)
print('unzip is good!!!')

# py3ews
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

# taxii2
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection
print("taxii2 is good!!!")


# pan-os-python
from panos.base import PanDevice
from lxml import etree
print("pan-os-python is good!!!")

# slackv3
import slack_sdk
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode.aiohttp import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.async_slack_response import AsyncSlackResponse
from slack_sdk.web.slack_response import SlackResponse
print('slackv3 is good!!!')

# google-api-py3
import google_auth_httplib2
import httplib2
from apiclient import discovery
from google.oauth2 import service_account
from googleapiclient.errors import HttpError
print('google-api-py3 is good!!!')


# boto3py3
import boto3
print('boto3py3 is good!!!')

# pyjwt3
import jwt
print('pyjwt3 is good!!!')

# joe-security
import jbxapi
print('joe-security is good!!!')

# slack
import slack
from slack.errors import SlackApiError
from slack.web.slack_response import SlackResponse
print('slack is good!!!')

# mlurlphishing
import numpy as np
import pandas
import sklearn
from bs4 import BeautifulSoup
import cv2 as cv
import tldextract
import dill
import catboost
from PIL import Image
print('mlurlphishing is good!!!')

# make sure regex is working cause in new versions there are problems
import regex
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')


# mlurlphishing
import numpy as np
import pandas
import sklearn
from bs4 import BeautifulSoup
import cv2 as cv
import dill
import catboost
from PIL import Image
print('mlurlphishing is good')


# ml
import torch.nn as nn
import os
import fasttext
import sklearn
import numpy
import pandas
import nltk
import lime
import tabulate
from Crypto.Hash import SHA256
import spacy
nlp = spacy.load('en_core_web_sm', disable=['tagger', 'parser', 'ner', 'textcat'])
doc = nlp('tokenize this sentence')
import demisto_ml
import catboost
import eli5
import langdetect
import onnx

def verify_stat(filename):
    res = os.stat(filename)
    assert res.st_uid == 4000
    assert res.st_gid == 4000
    assert oct(res.st_mode)[-3:] == '775'
verify_stat('/ml/encrypted_model.b')
verify_stat('/ml/nltk_data')
verify_stat('/ml/oob_evaluation.txt')
print('ml is good!!!')

