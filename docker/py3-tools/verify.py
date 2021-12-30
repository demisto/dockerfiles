# paho-mqtt
import paho.mqtt.client as mqtt

mqttc = mqtt.Client()


# geopy
import geopy


# tweepy
import tweepy
print("tweepy imported successfully.")


# marketo
from marketorestpython.client import MarketoClient
client = MarketoClient('AAA-123-CC', 'randomclientid', 'secret')
print("All is good. MarketoClient initialized")

# pyotrs
from importlib_metadata import version ; version('pyotrs')

# dxl
from dxlclient.broker import Broker
test = Broker("test.com")

# taxii2
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection
print("TAXII2 libraries loaded correctly!")

#pycef
import pycef
cef = "Jul 14 2020 00:49:42 myvxkp.manage.trendmicro.com CEF:0|Trend Micro|Apex Central|2019|WB:36|36|3|deviceExternalId=1 rt=Jun 21 2020 07:56:09 GMT+00:00 app=5 cnt=1 dpt=80 act=2 src=10.128.0.11 cs1Label=SLF_PolicyName cs1=Internal User Policy deviceDirection=2 cat=36 dvchost=CU-PRO1-8254-2 request=http://www.eicar.org/download/eicar.com.txt duser=TRENDMICROAPEX-\\admin shost=TRENDMICROAPEX- deviceProcessName=C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe cn3Label=Web_Reputation_Rating cn3=49 deviceFacility=Apex One cn2Label=SLF_SeverityLevel cn2=100 "
a = pycef.parse(cef)

# smartsheet
import smartsheet
from smartsheet.users import Users
print("smartsheet-sdk installed successfully")

# confluent-kafka
import confluent_kafka
print("all is good")

# treatconnect-tcex
import tcex
print("All good")


#crypto
from cryptography.fernet import Fernet
# Make sure cryptograph works
key = Fernet.generate_key()
print("All is good. cryptography generated a key: {}".format(key))


