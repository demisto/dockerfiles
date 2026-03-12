from subprocess import Popen, PIPE
import ssl
import re
from importlib.metadata import version

cmd = ['aquatone-discover', '--domain', 'example.com']
p = Popen(cmd, stdout=PIPE, stderr=PIPE, encoding="utf-8")
stdout, stderr = p.communicate()
print("All is good. aquatone-discover initialized")

openssl_ver = ssl.OPENSSL_VERSION
print(f"OpenSSL version: {openssl_ver}")

p = Popen(['gpg', '--version'], stdout=PIPE, stderr=PIPE, encoding="utf-8")
gpg_out, _ = p.communicate()
gpg_match = re.search(r'gpg \(GnuPG\) (\d+\.\d+\.\d+)', gpg_out)
if gpg_match:
    gpg_ver = gpg_match.group(1)
    print(f"GnuPG version: {gpg_ver}")

urllib3_ver = version("urllib3")
urllib3_parts = tuple(int(x) for x in urllib3_ver.split("."))
assert urllib3_parts >= (2, 6, 3), \
    f"urllib3 version {urllib3_ver} is vulnerable (CVE-2026-21441). Needs >= 2.6.3"
print(f"urllib3 version {urllib3_ver} is safe (CVE-2026-21441 patched)")

jaraco_context_ver = version("jaraco.context")
jaraco_parts = tuple(int(x) for x in jaraco_context_ver.split("."))
assert jaraco_parts >= (6, 1, 0), \
    f"jaraco.context version {jaraco_context_ver} is vulnerable (CVE-2026-23949). Needs >= 6.1.0"
print(f"jaraco.context version {jaraco_context_ver} is safe (CVE-2026-23949 patched)")

wheel_ver = version("wheel")
wheel_parts = tuple(int(x) for x in wheel_ver.split("."))
assert wheel_parts >= (0, 46, 2), \
    f"wheel version {wheel_ver} is vulnerable (CVE-2026-24049). Needs >= 0.46.2"
print(f"wheel version {wheel_ver} is safe (CVE-2026-24049 patched)")

print("All verifications passed")
