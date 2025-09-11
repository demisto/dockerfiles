# Last modified: 2025-09-12T01:10:57

# Last modified: 2025-09-12 01:10:57
FROM demisto/python3:3.12.11.4819260

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
