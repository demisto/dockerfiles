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


# Verify Node.js version (should be v22.x LTS)
run("node --version", "v22.")

# Verify npm is available
run("npm --version")

# Verify Go version (should be 1.26.x)
run("source ~/.bashrc && go version", "go1.26")

# Verify golangci-lint
run("source ~/.bashrc && golangci-lint --version", "golangci-lint")

# Verify Docker CLI
run("docker --version", "Docker")

# Verify Java
run("java -version", "17")

# Verify Poetry
run("source ~/.bashrc && poetry --version", "Poetry")

# Verify Git
run("git --version", "git version")

# Verify Neo4j
run("neo4j --version", "5.26.22")

# Verify gsutil
run("source ~/.bashrc && gsutil --version", "gsutil")

# Verify kubectl
run("source ~/.bashrc && kubectl version --client --output yaml", "clientVersion")

print("\nAll verifications passed!")