
# make sure regex is working cause in new versions there are problems
import regex
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')

# make sure that the iproute command is installed in py3-native image
import subprocess
subprocess.check_output(["ip", "route", "list"], text=True, stderr=subprocess.STDOUT)



##### verify auth-utils image support - start #####
# verify nmap
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.reportjson import ReportEncoder

NmapProcess('127.0.0.1').run()

# verify iputils
import subprocess
subprocess.check_output(
            ['ping', '-c', '3', '-q', '127.0.0.1'], stderr=subprocess.STDOUT, universal_newlines=True
        )

# verify netutils
import netaddr

##### verify auth-utils image support - end #####