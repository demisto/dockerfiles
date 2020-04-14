import sqlalchemy
import pymysql
import pyodbc
import psycopg2
import cx_Oracle

assert 'FreeTDS' in pyodbc.drivers()

try:
    # make sure oracle manages to load tns client libraries. 
    # Will fail but we want to be sure we don't fail on loading the driver
    cx_Oracle.connect()  
except Exception as ex:
    assert 'TNS:net service name is incorrectly specified' in str(ex)


print("All is good. All imported successfully")
