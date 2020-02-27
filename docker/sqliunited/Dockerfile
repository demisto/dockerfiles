
FROM demisto/python3:3.8.1.6120

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && apk add postgresql-dev gcc python3-dev musl-dev \
  && apk add --no-cache --virtual .build-deps gcc musl-dev

Run pip install cython
Run apk add g++ gcc unixodbc-dev
Run apk del .build-dependencies
