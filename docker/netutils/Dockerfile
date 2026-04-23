# Last modified: 2026-04-09T07:56:07.999309+00:00

FROM demisto/python3:3.12.13.7444307

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev \
  gcc musl-dev linux-headers build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache bind-tools openssl iputils nmap nmap-scripts tcpdump
