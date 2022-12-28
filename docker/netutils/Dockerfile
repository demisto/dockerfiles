# Last modified: 2022-12-28T00:48:54.348266+00:00
FROM demisto/iputils:1.0.0.42207

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools
