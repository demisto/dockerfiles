import email
import hashlib
import subprocess
import warnings
from collections import deque
from multiprocessing import Process

import lxml
import dateparser
import exchangelib
from cStringIO import StringIO
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
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib.services import EWSAccountService, EWSService
from exchangelib.util import add_xml_child, create_element
from exchangelib.version import (EXCHANGE_2007, EXCHANGE_2010,
                                 EXCHANGE_2010_SP2, EXCHANGE_2013,
                                 EXCHANGE_2016)
from future import utils as future_utils
from requests.exceptions import ConnectionError