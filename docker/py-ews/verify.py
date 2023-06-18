import email
import hashlib
import subprocess
import warnings
from collections import deque
from multiprocessing import Process

import lxml
import dateparser
import exchangelib
from io import StringIO
from exchangelib import (BASIC, DELEGATE, DIGEST, IMPERSONATION, NTLM, Account,
                         Body, Build, Configuration, Credentials, EWSDateTime,
                         EWSTimeZone, FileAttachment, Folder, HTMLBody,
                         ItemAttachment, Version)
from exchangelib.errors import (AutoDiscoverFailed, ErrorFolderNotFound,
                                ErrorInvalidIdMalformed,
                                ErrorInvalidPropertyRequest,
                                ErrorIrresolvableConflict, ErrorItemNotFound,
                                ErrorMailboxMoveInProgress,
                                ErrorMailboxStoreUnavailable,
                                ErrorNameResolutionNoResults, RateLimitError,
                                ResponseMessageError, TransportError)
from exchangelib.items import Contact, Item, Message
from exchangelib.protocol import BaseProtocol, Protocol
from exchangelib.services import EWSService
from exchangelib.services.common import EWSAccountService
from exchangelib.util import add_xml_child, create_element
from exchangelib.version import (EXCHANGE_2007, EXCHANGE_2010,
                                 EXCHANGE_2010_SP2, EXCHANGE_2013,
                                 EXCHANGE_2016, EXCHANGE_2019)
from future import utils as future_utils
from requests.exceptions import ConnectionError
from _sqlite3 import *
# verify that we support dh 1024
import requests
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS ='@SECLEVEL=1:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:' \
                         'ECDH+AES:DH+AES:RSA+ANESGCM:RSA+AES:!aNULL:!eNULL:!MD5:!DSS'
                         # same string used in CSP, override py3 hardening
requests.packages.urllib3.disable_warnings()
res = requests.get('https://dh1024.badssl.com/', verify=False)
res.raise_for_status()

# verify dateaparser works. We had a case that it failed with timezone issues
dateparser.parse("10 minutes")
