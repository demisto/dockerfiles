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
if ssl.OPENSSL_VERSION_INFOssl.OPENSSL_VERSION_INFO >= (3,0,0,0,0):
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
