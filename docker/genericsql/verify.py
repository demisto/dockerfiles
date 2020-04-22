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


# freetds test
engine = sqlalchemy.create_engine('mssql+pyodbc:///testuser:testpass@127.0.0.1:1433/TEST?driver=FreeTDS')
try:
    engine.execute('select 1 as [Result]')
except Exception as ex:
    assert "Can't open lib" not in str(ex), "Failed because of missing lib: " + str(ex)    

print("All is good. All imported successfully")
