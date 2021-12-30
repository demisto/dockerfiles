
FROM demisto/python3:3.9.9.25564

COPY requirements.txt .


RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


# Base: 67mb
# cloudshare, intezer, emoji, exifread, stomp.py, geopy, dns-python, 72mb
# algorithmia, asana, feed-parser-html, imap, pyjarm, python_zipfile 81mb
# paho-mqtt, python3-arrow, vertica, sendgrid, circleci, archer  85mb
# tweepy, tld, feed-parser, langdetect, gql, minio, ldap, pymongo 100mb
# cyjax, zabbix, jmespath, xlrd-py3, elasticsearch, aiohttp, stix2 120mb


# Bad:
# containes dockerfile changes: etl2pcap, pycef,
# staic version and conflict: gql vs graphql (removed)
# has verify: marketo, pyotrs, dxl
#------

# Contains:
# cloudshare, etl2pcap, intezer, emoji, exifread, stomp.py, geopy
# dns-python, algorithmia, asana, feed-parser-html, imap, pyjarm,
# python_zipfile, paho-mqtt, python3-arrow, vertica, sendgrid, circleci,
# cloakensdk, rsa-archer, tweepy, tld, feed-parser, langdetect, graphql,
# minio, marketo, ldap, pyotrs, dxl, pymongo, cyjax, zabbix, jmespath,
# taxii2, pycef, xlrd-py3, elasticsearch, aiohttp, stix2,
# , smartsheet, btfl-soup, argus-toolbelt, greynoise,
# unzip, polyswarm, slackv3,  carbon-black-cloud,


# Bad:
# conflicts: gql with graphql, pymisp with pymisp2, ***
# pip lock conflicts: pymisp2, opencti-v4, opencti,
# hard to get working: zeep, threatconnect-py3-sdk, crypto, accessdata, py42, confluent-kafka
# too big: nmap, dnstwist, threatconnect-tcex, slack, bs4-py3(1.1mb)

