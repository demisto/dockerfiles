
FROM demisto/python3:3.9.6.22912

COPY requirements.txt .

RUN apk add gcc && apk add linux-headers && apk add libc-dev && apk add libffi-dev \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt && pip install --upgrade pip \
  && apk del .build-dependencies
