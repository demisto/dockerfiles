import email
import hashlib
from email.policy import SMTP, SMTPUTF8
from io import StringIO
from multiprocessing import Process

import dateparser
from exchangelib import (
    BASIC,
    DELEGATE,
    DIGEST,
    IMPERSONATION,
    NTLM,
    Body,
    EWSDateTime,
    EWSTimeZone,
    FileAttachment,
    FolderCollection,
    HTMLBody,
    ItemAttachment,
    Version,
)
from exchangelib.errors import (
    ErrorCannotOpenFileAttachment,
    ErrorFolderNotFound,
    ErrorInvalidPropertyRequest,
    ErrorIrresolvableConflict,
    ErrorMailboxMoveInProgress,
    ErrorMailboxStoreUnavailable,
    ErrorMimeContentConversionFailed,
    ErrorNameResolutionNoResults,
    RateLimitError,
    TransportError,
)
from exchangelib.items import Contact, Item, Message
from exchangelib.services import EWSService
from exchangelib.util import add_xml_child, create_element
from exchangelib.version import (
    EXCHANGE_2007,
    EXCHANGE_2010,
    EXCHANGE_2010_SP2,
    EXCHANGE_2013,
    EXCHANGE_2013_SP1,
    EXCHANGE_2016,
    EXCHANGE_2019,
)
from exchangelib.version import VERSIONS as EXC_VERSIONS
from requests.exceptions import ConnectionError

# verify that we support dh 1024
import requests
import ssl
from urllib3.util import ssl_ as urllib3_ssl

urllib3_ssl.DEFAULT_CIPHERS = (
    'DEFAULT:@SECLEVEL=1:'
    'ECDHE+AESGCM:ECDHE+CHACHA20:'
    'DHE+AESGCM:DHE+CHACHA20:'
    'ECDH+AESGCM:DH+AESGCM:'
    'ECDH+AES:DH+AES:'
    'RSA+AESGCM:RSA+AES:'
    '!aNULL:!eNULL:!MD5:!DSS'
)
requests.packages.urllib3.disable_warnings()

ctx = ssl.create_default_context()
ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
session = requests.Session()
adapter = requests.adapters.HTTPAdapter()
adapter.init_poolmanager(10, 10, ssl_context=ctx)
session.mount('https://', adapter)
res = session.get('https://dh1024.badssl.com/', verify=False)
res.raise_for_status()

# verify dateparser works. We had a case that it failed with timezone issues
dateparser.parse("10 minutes")
