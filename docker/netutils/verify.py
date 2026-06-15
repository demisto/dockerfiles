

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

import dns.rdataclass  # noqa: F401
import dns.rdata  # noqa: F401

assert dns.rdatatype.from_text("A") == dns.rdatatype.RdataType.A
assert dns.rdataclass.from_text("IN") == dns.rdataclass.RdataClass.IN

# --- websockets (CertStream, ProofpointEmailSecurityEventCollector, RetarusSecureEmailGateway) ---
from websockets.sync.client import connect  # noqa: F401
from websockets.sync.connection import Connection  # noqa: F401
from websockets.exceptions import InvalidStatus, ConnectionClosed  # noqa: F401
from websockets import Data  # noqa: F401


print("netutils is good")