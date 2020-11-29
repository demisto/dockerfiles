#!/usr/bin/env python2.7
# -*- coding: utf8 -*-

# import pip

# pip.main(['-q', 'install', 'cymruwhois'])
# pip.main(['-q', 'install', 'dpkt'])
# pip.main(['-q', 'install', 'simplejson'])



try:
    import dpkt
except:
    print "Download dpkt"

try:
    import cymruwhois
except:
    print "Download cymruwhois"

try:
    import simplejson as json
except:
    print "Download simplejson"


import argparse
from core.Dispatcher import Dispatcher
from minepcaps import pcap_miner


VERSION = "1.0"

parser = argparse.ArgumentParser(description='Extract files from a pcap-file.')
parser.add_argument('input', metavar='PCAP_FILE', help='the input file')
parser.add_argument('output', metavar='OUTPUT_FOLDER', help='the target folder for extraction',
                    nargs='?', default='output')
parser.add_argument("-e", dest='entropy', help="use entropy based rawdata extraction",
                    action="store_true", default=False)
parser.add_argument("-nv", dest='verifyChecksums', help="disable IP/TCP/UDP checksum verification",
                    action="store_false", default=True)
parser.add_argument("--T", dest='udpTimeout', help="set timeout for UDP-stream heuristics",
                    type=int, default=120)
args = parser.parse_args()
readyPath = args.input
miner = pcap_miner(readyPath)
jsonResults = miner.summary2json()
pyResults = json.loads(jsonResults)
#print pyResults


#print 'pcapfex - Packet Capture Forensic Evidence Extractor - version %s' % (VERSION,)
#print '----------=------===-----=--------=---------=------------------' + '-'*len(VERSION) + '\n'

if not args.verifyChecksums:
    pyResults['verifiyChecksums'] = 'Packet checksum verification disabled.'
if args.entropy:
    pyResults['entropySetting'] = 'Using entropy and statistical analysis for raw extraction and classification of unknown data.'


dispatcher = Dispatcher(args.input, args.output, args.entropy,
                        verifyChecksums=args.verifyChecksums,
                        udpTimeout=args.udpTimeout,
                        )
results = dispatcher.run()
pyResults['files_found'] = results.filenamelist
print json.dumps(pyResults)

if(pyResults["counts"]):
    displayData = tableToMarkdown('PCAP Data Frequency Counts', pyResults["counts"])
if(pyResults["destination_ip_details"]):
    displayData += tableToMarkdown('Destination IP Details', pyResults["destination_ip_details"])
if(pyResults["dns_data"]):
    displayData += tableToMarkdown('DNS Details', pyResults["dns_data"])
if(pyResults["http_requests"]):
    displayData += tableToMarkdown('Http Requests', pyResults["http_requests"])
if(pyResults["flows"]):
    displayData += tableToMarkdown('Flow Data', pyResults["flows"])

demisto.results({'Type': entryTypes['note'], 'Contents': pyResults, 'EntryContext': {'pcap_results': pyResults}, 'ContentsFormat': formats['json'], 'HumanReadable': displayData})






