import warnings
import dateparser
import tldextract
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
search_string = 'Options = UnsafeLegacyRenegotiation'
if ssl.OPENSSL_VERSION_INFO >= (3,0,0,0,0):
    with open("/etc/ssl/openssl.cnf") as f:
        ssl_cnf = f.read()
        if search_string not in ssl_cnf:
            print ('openSSL version changed.\n\
Please validate SSL Legacy renegotiation error is not an issue.\n\
If SSL Legacy renegotiation error occurs, please refer to python3 image Dockerfile for reference.')
            exit(1)
print('openSSL version is good.')

import more_itertools
even, odd = more_itertools.partition(lambda num: num % 2 == 1, range(5))
assert len(tuple(even)) == 3
assert len(tuple(odd)) == 2
print('more_itertools installed correctly')
