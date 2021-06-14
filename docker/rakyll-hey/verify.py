import subprocess
from io import StringIO
import pandas as pd

try:
    output = subprocess.check_output('hey', stderr=subprocess.PIPE, text=True)
except subprocess.CalledProcessError as e:
    # hey returns -1 error when called with no URL
    if ' -n  Number of requests to run.' not in e.stderr:
        raise RuntimeError('hey was not installed properly')

test_col1_name = 'test-col1'
test_col2_name = 'test-col2'
col1 = pd.read_csv(StringIO(f'{test_col1_name},{test_col2_name}\nval1,val2'), usecols=[test_col1_name])[test_col1_name]
if len(col1) != 1:
    raise RuntimeError('pandas was not installed properly')
