from cryptography.fernet import Fernet
import msal
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from bs4 import BeautifulSoup
from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES
from nacl.public import PrivateKey, SealedBox
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)
sk = PrivateKey.generate()
assert SealedBox(sk).decrypt(SealedBox(sk.public_key).encrypt(b'test')) == b'test'
print('All is good. PyNaCl sealed box works')
