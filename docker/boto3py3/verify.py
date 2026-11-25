import subprocess

import boto3

aws_version = subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True)
print(aws_version.stdout or aws_version.stderr)
print(f"boto3py3 is good!!! boto3 version: {boto3.__version__}")
