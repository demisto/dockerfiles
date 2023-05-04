
FROM demisto/crypto:1.0.0.57519

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev libffi-dev gcc build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
