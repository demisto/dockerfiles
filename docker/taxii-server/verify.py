import warnings
warnings.simplefilter('error')

# make sure import doesn't generate warnings as seen: https://github.com/demisto/etc/issues/36452
# <frozen importlib._bootstrap>:219: RuntimeWarning: greenlet.greenlet size changed, may indicate binary incompatibility. Expected 144 from C header, got 152 from PyObject
from gevent.pywsgi import WSGIServer
