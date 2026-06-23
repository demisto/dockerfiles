# Last modified: 2026-06-23T04:52:49.564055+00:00
FROM demisto/python3:3.12.13.10381435


COPY requirements.txt .
RUN apk --update add --no-cache --virtual .build-dependencies \
    python3-dev \
    build-base \
    wget \
    git \
    libffi-dev \
    openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-dependencies
