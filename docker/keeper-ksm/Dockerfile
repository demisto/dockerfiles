# Last modified: 2025-12-21T14:11:58.351+00:00

FROM demisto/crypto:1.0.0.6308375

COPY requirements.txt .

# verify_licenses.py needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
