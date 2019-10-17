
FROM demisto/python3:3.7.4.2728

COPY requirements.txt .

RUN apk --update add --no-cache nmap nmap-scripts

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
