
FROM demisto/python3:3.8.1.5734

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && apk add postgresql-dev gcc python3-dev musl-dev \
  && apk add --no-cache g++ libc-dev unixodbc-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
