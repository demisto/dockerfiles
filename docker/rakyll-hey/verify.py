from subprocess import PIPE, Popen
from io import StringIO
import pandas as pd

p = Popen(['hey'], stdout=PIPE, stderr=PIPE, universal_newlines=True)
output, err = p.communicate()
if err or ' -n  Number of requests to run.' not in output:
    raise RuntimeError('hey was not installed properly')

test_col1_name = 'test-col1'
test_col2_name = 'test-col2'
col1 = pd.read_csv(StringIO(f'{test_col1_name},{test_col2_name}\nval1,val2'), usecols=[test_col1_name])[test_col1_name]
if len(col1) != 1:
    raise RuntimeError('pandas was not installed properly')
