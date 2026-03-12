import subprocess
import sys

import sane_doc_reports


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


# Verify sane_doc_reports is importable (original test)
print("OK: sane_doc_reports imported successfully")

# Verify svgexport is installed (installed globally via npm in Dockerfile)
run("svgexport --help", "Usage")

print("\nAll verifications passed for sane-doc-reports!")
