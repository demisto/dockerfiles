import warnings
import dateparser
import subprocess

# set warnings to throw an error
warnings.simplefilter("error")
d = dateparser.parse('1 day')
print("all is good managed to parse: {}".format(d))

res = subprocess.check_output(['pwsh', '--version'])
assert res.startswith('PowerShell 7')

# cve-2021-3177 See: https://bugs.python.org/issue42938
# verify we are patched
from ctypes import *
c_double.from_param(1e300)
print("all is good")
