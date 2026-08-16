import subprocess

import boto3

print('boto3 import successful')

result = subprocess.run(['aws', '--version'], capture_output=True, text=True)
if result.returncode != 0:
    raise RuntimeError(f'awscli was not installed properly: {result.stderr}')
print(f'awscli is good: {result.stdout or result.stderr}')
