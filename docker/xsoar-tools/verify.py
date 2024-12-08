import os
os.environ['DEMIST_SDK_SKIP_LOGGER_SETUP'] = 'true'
import demisto_sdk  # noqa: F401
os.environ['DEMIST_SDK_SKIP_LOGGER_SETUP'] = ''

print('demisto-sdk is good')