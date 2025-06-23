# Last modified: 2025-06-10T12:44:14.348419+00:00
FROM demisto/python3:3.12.8.3720084

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev \
  gcc musl-dev linux-headers build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl iputils nmap nmap-scripts tcpdump
