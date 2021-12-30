
FROM demisto/python3:3.9.9.25564

COPY requirements.txt .


RUN pip3 install --no-cache-dir --upgrade pip \
&& apk --update add --no-cache \
    iputils \
    openssh-client \
    p7zip unrar \
    libffi \
&& apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
     libffi-dev openssl-dev \
     libxml2-dev libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
&& mkdir /var/opt/etl && wget -O /var/opt/etl/etl2pcap.py https://raw.githubusercontent.com/aaptel/etl2pcap/45c1a843078c757a0e5e49b30c89c77221ae9afc/etl2pcap.py


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

