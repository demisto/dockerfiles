from cryptography.fernet import Fernet
import msal
from bs4 import BeautifulSoup
# Make sure cryptograph works
key = Fernet.generate_key()

# Make sure MD4 is enabled:
import hashlib
hashlib.algorithms_available
assert 'md4' in hashlib.algorithms_available

print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)
