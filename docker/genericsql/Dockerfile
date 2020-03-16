
FROM demisto/python3:3.8.1.6442

COPY requirements.txt .
COPY odbcinst.ini /etc/odbcinst.ini

RUN apk --update add --no-cache unixodbc mariadb postgresql freetds

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  gcc libc-dev g++ libffi-dev unixodbc-dev mariadb-dev postgresql-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
