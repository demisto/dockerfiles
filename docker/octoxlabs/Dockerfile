# Last modified: 2025-05-15T11:35:11.601428+00:00
FROM demisto/python3:3.12.8.3296088

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
