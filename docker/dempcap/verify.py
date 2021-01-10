import dpkt
import cymruwhois
import simplejson
import sys
path = "/app/pcapminey/"

if path not in sys.path:
    sys.path.append(path)

from core.Dispatcher import Dispatcher

from minepcaps import pcap_miner

print('all is good')