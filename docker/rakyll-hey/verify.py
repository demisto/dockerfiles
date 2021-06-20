import subprocess

try:
    output = subprocess.check_output('hey', stderr=subprocess.PIPE, text=True)
except subprocess.CalledProcessError as e:
    # hey returns -1 error when called with no URL
    if ' -n  Number of requests to run.' not in e.stderr:
        raise RuntimeError('hey was not installed properly')
