import subprocess
import sys
from pathlib import Path

if not Path('/app').exists() \
        or not Path('/app/reportsServer').exists() \
        or not Path('/app/dist').exists():
    print("reportsServer's dependencies paths are not found.")
    sys.exit(1)

res = subprocess.run(['./reportsServer'], cwd='/app',
                     shell=True, executable='/bin/bash', capture_output=True)

# Check that the executable is running (path will no be supplied)
if b"ERR_INVALID_ARG_TYPE" not in res.stdout:
    print("Not working binary")
    sys.exit(1)

print("Validation passed for sane-pdf-reports")



## Now checking the sane-doc-reports
import sane_doc_reports

print("Validation passed for sane-doc-reports")

