
FROM demisto/python3:3.9.9.25564

COPY requirements.txt .


RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


# This is an aggregation docker image, which includes the following images:
# Base size: 67mb
# Images:
# cloudshare, intezer, emoji, exifread, stomp.py, geopy, dns-python, 72mb
# asana, feed-parser-html, imap, pyjarm, python_zipfile 81mb
# paho-mqtt, vertica, sendgrid, archer  85mb
# tweepy, tld, feed-parser, langdetect, graphql, minio, ldap, pymongo 100mb
# cyjax, zabbix, jmespath, xlrd-py3, elasticsearch, aiohttp, stix2 120mb

