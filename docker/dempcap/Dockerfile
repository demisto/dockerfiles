
FROM demisto/python:2.7.18.37800

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python2-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Copy the pcapminey directory contents into the container at /app
ADD pcapminey /app/pcapminey
