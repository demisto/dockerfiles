import pysnmp
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import websocket as wsc
from websocket import WebSocketApp
import snap7
import pandas
import orionsdk
import dns.resolver
import pyads
import bs4

def lookup_dns_record(domain, record_type='A'):
    """
    Performs a DNS lookup for the specified domain and record type.

    Args:
        domain (str): The domain to look up.
        record_type (str, optional): The type of DNS record to look up (e.g., 'A', 'MX', 'TXT'). Default is 'A'.

    Returns:
        list: A list of DNS records for the specified domain and record type.
    """
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        return [str(record) for record in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        return []
    except Exception as e:
        return []


snap7client = snap7.client.Client()
swis = orionsdk.SwisClient("server", "username", "password")
lookup = lookup_dns_record("google.com")
print(f"pyads version: {pyads.__version__}")
print(f"bs4 version: {bs4.__version__}")
print("All is good. PANW IoT python packages imported successfully!")