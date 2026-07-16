import os
import demisto_sdk  # noqa: F401
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, FileType
from demisto_sdk.commands.common.logger import DEFAULT_CONSOLE_THRESHOLD, logging_setup
from demisto_sdk.commands.common.tools import _get_file_id, get_file_displayed_name, find_type, get_file
from demisto_sdk.commands.split_yml.extractor import Extractor

print('demisto-sdk is good')

import cryptography.fernet  # noqa: F401
_ = cryptography.fernet.__name__

print('cryptography is good')

import ujson  # noqa: F401
_ = ujson.__name__

print('ujson is good')

import orjson  # noqa: F401
_ = orjson.__name__

print('orjson is good')

import nltk  # noqa: F401  # noqa: F401
_ = nltk.__name__

print('nltk is good')
