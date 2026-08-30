import requests_ntlm
from spnego._ntlm_raw.crypto import ntowfv1

# Make sure NTLM hashing works without OpenSSL's md4 (XSUP-75734):
assert ntowfv1("pass").hex() == "36aa83bdcab3c9fdaf321ca42a31c3fc"

print("all is good, NTLM hashing is working")
