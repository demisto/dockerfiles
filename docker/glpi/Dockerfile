
FROM demisto/python3:3.10.11.59070

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git musl-dev libffi-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
