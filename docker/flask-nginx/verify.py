import subprocess
from flask_cors import CORS
from taxii2client.v21 import Server

res = subprocess.check_output(['nginx', '-V'], text=True, stderr=subprocess.STDOUT)
print(res)
# verify that we are using nginx 1.x
assert 'nginx/1.' in res

# verify that nginx test passes
res = subprocess.check_output(['nginx', '-t'], text=True, stderr=subprocess.STDOUT)
print(res)
