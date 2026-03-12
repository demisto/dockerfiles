import subprocess
import sys


def run(cmd, expected_substring=None):
    """Run a command and optionally check output contains expected substring."""
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()
    output = stdout.decode('utf-8', errors='replace').strip() + stderr.decode('utf-8', errors='replace').strip()
    if result.returncode != 0:
        print("FAIL: '%s' exited with code %d" % (cmd, result.returncode))
        print("  Output: %s" % output)
        sys.exit(1)
    if expected_substring and expected_substring not in output:
        print("FAIL: '%s' output does not contain '%s'" % (cmd, expected_substring))
        print("  Output: %s" % output)
        sys.exit(1)
    print("OK: %s -> %s" % (cmd, output[:120]))


# Verify Python 2.7
run("python --version", "2.7")

# Verify pip
run("pip --version", "pip")

# Verify Docker CLI
run("docker --version", "Docker")

# Verify Go version (should be 1.26.x)
run("export GOROOT=/usr/local/go && export PATH=$PATH:$GOROOT/bin && go version", "go1.26")

# Verify Ruby
run("ruby --version", "ruby")

# Verify bundler
run("bundler --version", "Bundler")

# Verify Java (OpenJDK 11)
run("java -version", "11")

# Verify protoc
run("protoc --version", "libprotoc")

# Verify Google Cloud SDK
run("gcloud --version", "Google Cloud SDK")

# Verify Git
run("git --version", "git version")

# Verify dnsutils (dig is available)
run("which dig", "dig")

# Verify stix Python package
run("python -c \"import stix; print('stix ok')\"", "stix ok")

# Verify boto3 Python package
run("pip show boto3", "boto3")

print("\nAll verifications passed for gitlab-ci!")
