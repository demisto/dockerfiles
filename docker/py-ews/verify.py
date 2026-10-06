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
from ntlm_auth.compute_hash import _ntowfv1
from requests.exceptions import ConnectionError
from _sqlite3 import *

import ssl

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


class _WeakDHAdapter(HTTPAdapter):
    """HTTPAdapter that lowers the OpenSSL security level to accept 1024-bit DH."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx,
            **pool_kwargs,
        )


requests.packages.urllib3.disable_warnings()

session = requests.Session()
session.mount("https://", _WeakDHAdapter())
res = session.get("https://dh1024.badssl.com/", verify=False)
res.raise_for_status()

# verify dateaparser works. We had a case that it failed with timezone issues
dateparser.parse("10 minutes")

# Make sure MD4 is enabled - NTLM authentication (XSUP-76118) cannot work without it.
print(hashlib.algorithms_available)
assert 'md4' in hashlib.algorithms_available
hashlib.new('md4', b"text")

# Verify the exact frame that NTLM authentication goes through
assert _ntowfv1('Password01').hex() == '7100a909c7ff05b266af3c42ec058c33'
