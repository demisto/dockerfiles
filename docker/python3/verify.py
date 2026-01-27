import warnings
import dateparser
import tldextract
import os
# set warnings to throw an error
warnings.simplefilter("error")
d = dateparser.parse('1 day')
extract = tldextract.TLDExtract(cache_dir=False,suffix_list_urls=None)
t = extract('*test-test.com')
print("all is good managed to parse: {}".format(d))

# cve-2021-3177 See: https://bugs.python.org/issue42938
# verify we are patched
from ctypes import *
print(c_double.from_param(1e300))
print("all is good cve-2021-3177 is patched")

import ssl
if ssl.OPENSSL_VERSION_INFO >= (3,0,0,0,0):
    if os.path.exists("/etc/ssl/openssl.cnf"):
        # in python3 (alpine) the path to openssl conf is /etc/ssl/openssl.cnf
        ssl_cnf_file_path = "/etc/ssl/openssl.cnf"
    else:
        # in python3 (ubi) the path to openssl conf is /etc/pki/tls/openssl.cnf
        ssl_cnf_file_path = "/etc/pki/tls/openssl.cnf"
    search_string = 'Options = UnsafeLegacyRenegotiation'
    with open(ssl_cnf_file_path) as f:
        ssl_cnf = f.read()
        if search_string not in ssl_cnf:
            print('openSSL version changed.\n\
Please validate SSL Legacy renegotiation error is not an issue.\n\
If SSL Legacy renegotiation error occurs, please refer to python3 image Dockerfile for reference.')
            exit(1)
print('openSSL version is good.')

import more_itertools
even, odd = more_itertools.partition(lambda num: num % 2 == 1, range(5))
assert len(tuple(even)) == 3
assert len(tuple(odd)) == 2
print('more_itertools installed correctly')

from defusedxml.ElementTree import fromstring
xml = '<?xml version="1.0" encoding="UTF-8"?>' \
      '<book>' \
      '<name>A Song of Ice and Fire</name>' \
      '</book>'

xml_obj = fromstring(xml)
assert xml_obj.tag == 'book'
print('defusedxml installed correctly')

import setuptools
print(f'Using setuptools version {setuptools.__version__}')

assert os.path.exists("/var/public_list.dat")
print("public_list.dat for TLDextract exists")

# XSUP-62124: Verify Microsoft TLS G2 ECC certificates are installed and working
import urllib.request
import certifi

# Check if Microsoft certificates are in certifi's CA bundle
print("Checking certifi CA bundle location:", certifi.where())
with open(certifi.where(), 'r') as f:
    certifi_content = f.read()
    if 'Microsoft TLS ECC Root G2' in certifi_content or 'Microsoft TLS G2 ECC CA OCSP 02' in certifi_content:
        print("✓ Microsoft TLS G2 ECC certificates found in certifi's CA bundle")
    else:
        print("ERROR: Microsoft TLS G2 ECC certificates NOT found in certifi's CA bundle")
        exit(1)

# Test with requests library (uses certifi's CA bundle) - this is what integrations use
try:
    import requests
    response = requests.get("https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20260119.json", timeout=10)
    if response.status_code == 200:
        print("✓ requests library SSL connection to download.microsoft.com successful (certifi CA bundle)")
    else:
        print(f"Warning: Unexpected response status {response.status_code} from download.microsoft.com")
except requests.exceptions.SSLError as e:
    print(f"ERROR: requests library SSL certificate verification failed for download.microsoft.com: {e}")
    print("This means the Microsoft certificates are not properly installed in certifi's CA bundle")
    exit(1)
except Exception as e:
    print(f"Warning: Could not test requests library connection: {e}")
