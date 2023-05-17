
FROM demisto/python3:3.10.11.59070

COPY requirements.txt .


RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libffi-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


# This is an aggregation docker image, which includes the following images:
# Base size: 67mb
# Images:
# cloudshare, intezer, emoji, exifread, stomp.py, geopy, dns-python, 72mb
# algorithmia, asana, feed-parser-html, imap, pyjarm, python_zipfile 81mb
# paho-mqtt, python3-arrow, vertica, sendgrid, circleci, archer  85mb
# tweepy, tld, feed-parser, langdetect, gql, minio, ldap, pymongo 100mb
# cyjax, zabbix, jmespath, xlrd-py3, elasticsearch, aiohttp, stix2 120mb

