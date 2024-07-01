
# make sure regex is working cause in new versions there are problems
import regex
from psutil import Process
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')

# make sure that the iproute command is installed in py3-native image
import subprocess
subprocess.check_output(["ip", "route", "list"], text=True, stderr=subprocess.STDOUT)

import pychrome
print(f'Using pychrome version {pychrome.__version__}')

import pdf2image
print(f'Using poppler version: {pdf2image.pdf2image._get_poppler_version("pdftocairo")}')
