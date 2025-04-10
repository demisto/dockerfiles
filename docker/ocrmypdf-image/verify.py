import subprocess
result = subprocess.run(["ocrmypdf", "--version"], capture_output=True)
assert result.returncode == 0

