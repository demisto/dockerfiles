
FROM demisto/python3:3.10.10.49934

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install git+https://github.com/SSHcom/privx-sdk-for-python.git@v34.0.0#egg=privx_api \
  && apk del .build-dependencies
