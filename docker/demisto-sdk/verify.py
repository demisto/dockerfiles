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


# Verify demisto-sdk is installed and working
run("demisto-sdk --version", "demisto-sdk")

# Verify Node.js is available (setup_24.x)
run("node --version", "v24.")

# Verify npm is available
run("npm --version")

# Verify Docker CLI is available
run("docker --version", "Docker")

# Verify jsdoc-to-markdown is installed
run("jsdoc2md --version", "9.")

# Verify git is available
run("git --version", "git version")

# Verify MDX server can start (original test)
from demisto_sdk.commands.common.hook_validations.readme import ReadMeValidator, mdx_server_is_up

with ReadMeValidator.start_mdx_server():
    assert mdx_server_is_up()

print("OK: MDX server started successfully")

print("\nAll verifications passed for demisto-sdk!")
