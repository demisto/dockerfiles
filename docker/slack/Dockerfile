
FROM demisto/python3:3.7.5.3066

COPY requirements.txt .

RUN apk --update add --no-cache libffi

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  libffi-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
