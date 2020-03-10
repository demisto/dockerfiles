
FROM demisto/python3:3.8.1.6120

COPY requirements.txt .

RUN apk update

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && apk add gcc libc-dev g++ libffi-dev libxml2 unixodbc-dev mariadb-dev postgresql-dev \
  && pip install pyodbc \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
