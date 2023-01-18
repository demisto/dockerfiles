from cryptography.fernet import Fernet
import msal
import hashlib
from bs4 import BeautifulSoup
# Make sure cryptograph works
key = Fernet.generate_key()

# Make sure MD4 is enabled:
hashlib.algorithms_available
assert 'md4' in hashlib.algorithms_available
hashlib.new('md4', b"text")

print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)
