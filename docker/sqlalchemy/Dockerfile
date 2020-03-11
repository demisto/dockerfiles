
FROM demisto/python3:3.8.1.6120

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && apk add gcc libc-dev g++ libffi-dev libxml2 unixodbc-dev mariadb-dev postgresql-dev freetds-dev \
  && pip install pyodbc \
  && echo -e "[FreeTDS]\nDescription=FreeTDS Driver\nDriver=/usr/lib/libtdsodbc.so\nSetup=/usr/lib/libtdsodbc.so.0\n" > /etc/odbcinst.ini \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
