import subprocess
import os

"""
Check that nuclei is properly installed.
"""
p = subprocess.run(["/app/nuclei -version"], capture_output=True, shell=True, encoding="utf8")

if p.returncode > 0:
    print("Error running nuclei")
    print(p.stdout)
    print(p.stderr)
    exit(p.returncode)
elif "Current Version" in p.stderr:
    print("All is good. nuclei initialized")

"""
Check that we have our nuclei-templates in place
"""

if os.path.isfile("/app/nuclei-templates/subdomain-takeover/detect-all-takeovers.yaml"):
    print("All is good. nuclei-templates initialized")
else:
    print("nuclei-templates STO file is missing.")
    exit(2)
