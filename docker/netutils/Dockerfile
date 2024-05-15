# Last modified: 2024-04-17T08:08:33.560504+00:00
FROM demisto/python3:3.10.14.92207

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl iputils nmap nmap-scripts
