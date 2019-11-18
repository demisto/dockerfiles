from cryptography.fernet import Fernet
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))
