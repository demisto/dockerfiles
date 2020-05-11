import sys
import traceback
import json
import os
import hashlib
from datetime import timedelta
from io import StringIO
import logging
import warnings
import subprocess
import email
from requests.exceptions import ConnectionError
from collections import deque

from multiprocessing import Process
import exchangelib
from exchangelib.errors import ErrorItemNotFound, ResponseMessageError, TransportError, RateLimitError, \
    ErrorInvalidIdMalformed, \
    ErrorFolderNotFound, ErrorMailboxStoreUnavailable, ErrorMailboxMoveInProgress, \
    AutoDiscoverFailed, ErrorNameResolutionNoResults, ErrorInvalidPropertyRequest, ErrorIrresolvableConflict
from exchangelib.items import Item, Message, Contact
from exchangelib.services.common import EWSService, EWSAccountService
from exchangelib.util import create_element, add_xml_child
from exchangelib import IMPERSONATION, DELEGATE, Account, Credentials, \
    EWSDateTime, EWSTimeZone, Configuration, NTLM, DIGEST, BASIC, FileAttachment, \
    Version, Folder, HTMLBody, Body, Build, ItemAttachment
from exchangelib.version import EXCHANGE_2007, EXCHANGE_2010, EXCHANGE_2010_SP2, EXCHANGE_2013, EXCHANGE_2016
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
