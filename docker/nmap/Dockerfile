
FROM demisto/python3:3.12.16.14990175

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache nmap nmap-scripts

RUN apk --update add --no-cache --upgrade "krb5-libs>=1.22.3-r0"

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
