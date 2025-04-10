from cryptography.fernet import Fernet
import msal
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from bs4 import BeautifulSoup
from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)
