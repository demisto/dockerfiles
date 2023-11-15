import pychrome
import subprocess

print(f'Using pychrome version {pychrome.__version__}')

try:
    command = ['bash', '/start_chrome_headless.sh']
    result = subprocess.call(command, stdout=subprocess.PIPE)
    assert "Chrome is running" in result.stdout
except Exception as ex:
    print(f'Exception running chrome headless, {ex}')
    assert False

print('All is good!!!')
