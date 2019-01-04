FROM demisto/python3:1.5.0.53

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base libxml2-dev libxslt-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
