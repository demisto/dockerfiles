
FROM demisto/python3:3.10.11.59581

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget libxml2-dev libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
