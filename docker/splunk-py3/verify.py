import splunklib.client

try:
    splunklib.client.connect()
except OSError:
    pass
else:
    raise Exception('failed')
