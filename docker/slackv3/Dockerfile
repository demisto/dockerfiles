
FROM demisto/python3:3.10.12.63474

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
