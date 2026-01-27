

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

# verify aiohttp
import aiohttp

# verify aiolimiter
from aiolimiter import AsyncLimiter