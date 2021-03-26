import warnings
import dateparser
import subprocess

# set warnings to throw an error
warnings.simplefilter("error")
d = dateparser.parse('1 day')
print("all is good managed to parse: {}".format(d))

res = subprocess.check_output(['pwsh', '--version'])
assert res.startswith('PowerShell 7')
