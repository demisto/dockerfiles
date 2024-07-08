# Last modified: 2024-07-08T12:45:22.167118+00:00
FROM demisto/python3:3.11.9.101916

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl iputils nmap nmap-scripts
