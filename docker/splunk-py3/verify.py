import splunklib.client

try:
    splunklib.client.connect()
except ConnectionRefusedError as error:
    if not error.strerror == 'Connection refused':
        raise error
else:
    raise Exception('failed')
