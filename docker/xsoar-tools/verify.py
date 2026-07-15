import os
import demisto_sdk  # noqa: F401
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, FileType
from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.common.logger import DEFAULT_CONSOLE_THRESHOLD, logging_setup
from demisto_sdk.commands.common.tools import _get_file_id, get_file_displayed_name, find_type, get_file

print('demisto-sdk is good')

from cryptography.fernet import Fernet

print('cryptography is good')

import ujson  # noqa: F401
_ = ujson.__name__

print('ujson is good')

import orjson  # noqa: F401
_ = orjson.__name__

print('orjson is good')

import nltk  # noqa: F401  # noqa: F401

print('nltk is good')
