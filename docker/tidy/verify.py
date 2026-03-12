import subprocess
from importlib.metadata import version

# Verify ansible-runner is importable
import ansible_runner
print("ansible_runner imported successfully")

# Verify CVE-2026-23949: jaraco.context >= 6.1.0
jaraco_context_ver = version("jaraco.context")
jaraco_parts = tuple(int(x) for x in jaraco_context_ver.split("."))
assert jaraco_parts >= (6, 1, 0), \
    f"jaraco.context version {jaraco_context_ver} is vulnerable (CVE-2026-23949). Needs >= 6.1.0"
print(f"jaraco.context version {jaraco_context_ver} is safe (CVE-2026-23949 patched)")

# Verify CVE-2026-24049: wheel >= 0.46.2
wheel_ver = version("wheel")
wheel_parts = tuple(int(x) for x in wheel_ver.split("."))
assert wheel_parts >= (0, 46, 2), \
    f"wheel version {wheel_ver} is vulnerable (CVE-2026-24049). Needs >= 0.46.2"
print(f"wheel version {wheel_ver} is safe (CVE-2026-24049 patched)")

print("All verifications passed")
