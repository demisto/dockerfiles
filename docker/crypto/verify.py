from cryptography.fernet import Fernet
import msal
import OpenSSL.crypto
from bs4 import BeautifulSoup
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)
