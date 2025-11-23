import hashlib
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl

import dateparser
import pymysql
import sqlalchemy
from sqlalchemy.engine.url import URL
from sqlalchemy.sql import text
import psycopg2
import pyodbc
import cx_Oracle
import teradatasqlalchemy

assert 'FreeTDS' in pyodbc.drivers()
assert 'ODBC Driver 18 for SQL Server' in pyodbc.drivers(), pyodbc.drivers()

try:
    # make sure oracle manages to load tns client libraries.
    # Will fail but we want to be sure we don't fail on loading the driver
    cx_Oracle.connect()
except Exception as ex:
    assert 'ORA-12162' in str(ex)

# freetds test
engine = sqlalchemy.create_engine('mssql+pyodbc:///testuser:testpass@127.0.0.1:1433/TEST?driver=FreeTDS')
try:
    engine.execute('select 1 as [Result]')
except Exception as ex:
    assert "Can't open lib" not in str(ex), "Failed because of missing lib: " + str(ex)

# teradata test: raises sqlalchemy.exc.NoSuchModuleError if the plugin is not installed
eng = sqlalchemy.create_engine('teradatasql://guest:foo@bar') 

#  test there no missing 'cryptography' module
try:
    pymysql._auth.sha2_rsa_encrypt(b'test', b'test', 'test')
except TypeError as ex:
    msg = str(ex)
    assert (
        ("Cannot convert" in msg and "buffer" in msg)
        or ("bytes" in msg or "bytestring" in msg)
    ), "Expected TypeError when passing str to sha2_rsa_encrypt"


print("All is good. All imported successfully")
