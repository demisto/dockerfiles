import pysnmp
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import websocket as wsc
from websocket import WebSocketApp
import snap7
import pandas
import orionsdk

snap7client = snap7.client.Client()
swis = orionsdk.SwisClient("server", "username", "password")
print("All is good. PANW IoT python packages imported successfully!")
