
# make sure regex is working cause in new versions there are problems
import regex
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')

# make sure that the iproute command is installed in py3-native image
import subprocess
subprocess.check_output(["ip", "route", "list"], text=True, stderr=subprocess.STDOUT)