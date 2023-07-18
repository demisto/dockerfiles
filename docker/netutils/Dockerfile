# Last modified: 2023-06-16T04:34:35.524307+00:00
FROM demisto/iputils:1.0.0.63703

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git curl \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl
