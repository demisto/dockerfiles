import subprocess

python_version, _ = subprocess.Popen(['python3', '-V'], stdout=subprocess.PIPE).communicate()
python_version = python_version.decode().strip('\n')
assert '3' in python_version, f'No python3 in "python3" command {python_version=}'

# python_version, _ = subprocess.Popen(['python', '-V'], stdout=subprocess.PIPE).communicate()
# python_version = python_version.decode().strip('\n')
# assert '2.7' in python_version, f'No python2 in "python" command. {python_version=}'

# assert subprocess.Popen(['demisto-sdk', '--version']).wait() != 0, 'Could not run demisto-sdk'