
FROM demisto/python3:3.10.1.25933

COPY requirements.txt .

RUN pip install --upgrade pip \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev gcc linux-headers libc-dev libffi-dev\
  build-base wget git && pip install --no-cache-dir -r requirements.txt && apk del .build-dependencies
