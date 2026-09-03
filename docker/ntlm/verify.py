import requests
import requests_ntlm
from requests_ntlm import HttpNtlmAuth
from spnego._ntlm_raw.crypto import ntowfv1

# Make sure NTLM hashing works without OpenSSL's md4 (XSUP-75734):
# pyspnego >=0.5.2 ships a pure-Python md4; earlier versions called
# hashlib.new('md4'), which fails under OpenSSL 3.x.
assert ntowfv1("pass").hex() == "36aa83bdcab3c9fdaf321ca42a31c3fc"

# The consuming integrations (MicrosoftAdvancedThreatAnalytics, CyberArkAIM_v2,
# VaronisDataSecurityPlatform) all build HttpNtlmAuth with a 'DOMAIN\user' name.
auth = HttpNtlmAuth("DOMAIN\\user", "pass")
assert isinstance(auth, requests.auth.AuthBase)
assert auth.username == "DOMAIN\\user"
assert auth.password == "pass"
assert auth.send_cbt is True

# The third 'session' argument is a documented no-op but must stay accepted.
assert HttpNtlmAuth("DOMAIN\\user", "pass", requests.Session()) is not None
assert requests_ntlm.__all__ == ("HttpNtlmAuth",)

# NTLM authenticates the connection, so the auth handler must keep it alive
# and register its 401 handler. Nothing below touches the network.
prepared = requests.Request(
    "POST", "http://ntlm.invalid/auth", data="grant_type=client_credentials"
).prepare()
prepared = auth(prepared)
assert prepared.headers["Connection"] == "Keep-Alive"
assert auth.response_hook in prepared.hooks["response"]

session = requests.Session()
session.auth = auth
assert callable(session.auth)

# A non-401 response must pass straight through.
ok = requests.Response()
ok.status_code = 200
assert auth.response_hook(ok) is ok

print("all is good, NTLM hashing and requests-ntlm auth flow are working")
