# Last modified: 2023-04-27T16:36:27.208321+00:00
FROM demisto/python3:3.10.11.56082

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
