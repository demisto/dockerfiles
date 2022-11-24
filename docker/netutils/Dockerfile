# Last modified: 2022-11-24T14:16:50.783149+00:00
FROM demisto/iputils:1.0.0.38267

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools
