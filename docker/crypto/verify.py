from cryptography.fernet import Fernet
import msal
import html2text
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
print(msal.oauth2cli.assertion.JwtAssertionCreator('', 'All is good. msal was imported successfully').algorithm)
