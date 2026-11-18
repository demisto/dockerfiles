import json

from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from libnmap.reportjson import ReportEncoder

# verify the real nmap binary runs and its XML output is parsable (used by the Nmap integration)
nm = NmapProcess("127.0.0.1", options="-sT -Pn -p 1")
assert nm.run() == 0, f"nmap failed: {nm.stderr}"
report = NmapParser.parse(nm.stdout)
assert report.version, "nmap version missing from report"
json.dumps(report, cls=ReportEncoder)

# verify nmap-scripts (NSE) are available - the "NMAP - Banner Check" playbook uses --script=banner
nm = NmapProcess("127.0.0.1", options="-sT -Pn -p 1 --script=banner")
assert nm.run() == 0, f"nmap --script=banner failed: {nm.stderr}"

print("nmap is good")
