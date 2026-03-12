import subprocess
import sys


def run(cmd, expected_substring=None):
    """Run a command and optionally check output contains expected substring."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout.strip() + result.stderr.strip()
    if result.returncode != 0:
        print(f"FAIL: '{cmd}' exited with code {result.returncode}")
        print(f"  Output: {output}")
        sys.exit(1)
    if expected_substring and expected_substring not in output:
        print(f"FAIL: '{cmd}' output does not contain '{expected_substring}'")
        print(f"  Output: {output}")
        sys.exit(1)
    print(f"OK: {cmd} -> {output[:120]}")


# Verify bake.js works (original test)
from subprocess import run as subprocess_run
process = subprocess_run(['/bin/sh', '-c', 'node /bake.js Test [] {}'], capture_output=True, text=True)
assert process.stdout == "Test\n", f"bake.js test failed: {process.stdout!r}"
print("OK: bake.js -> Test")

# Verify magic.js works (original test)
process = subprocess_run(['/bin/sh', '-c', 'node /magic.js "4f 6e 65 2c 20 74 77 6f 2c 20 74 68 72 65 65 2c 20 66 6f 75 72 2e" {}'], capture_output=True, text=True)
assert process.stdout, "magic.js returned empty output"
print(f"OK: magic.js -> {process.stdout.strip()[:80]}")

# Verify Node.js is available
run("node --version")

# Verify npm is available
run("npm --version")

# Verify cyberchef-node is installed
run("node -e \"require('cyberchef-node')\"")

# Verify jsonpath-plus is installed within cyberchef-node
run("node -e \"require('cyberchef-node/node_modules/jsonpath-plus')\"")

# Verify tar package is installed at expected version within cyberchef-node
run("node -e \"const p = require('/usr/local/lib/node_modules/cyberchef-node/node_modules/tar/package.json'); console.log(p.version)\"", "7.5.")

# Verify minimatch package is installed at expected version within cyberchef-node
run("node -e \"const p = require('/usr/local/lib/node_modules/cyberchef-node/node_modules/minimatch/package.json'); console.log(p.version)\"", "10.")

print("\nAll verifications passed for cyberchef!")
