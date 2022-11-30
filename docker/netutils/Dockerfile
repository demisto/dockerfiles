# Last modified: 2022-11-30T02:17:18.215831+00:00
FROM demisto/iputils:1.0.0.39768

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools
