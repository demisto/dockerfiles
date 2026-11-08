# Last modified: 2026-11-08T06:26:51.526665+00:00
FROM demisto/python3:3.12.14.13495286

ENV MSGPACK_PUREPYTHON=1

COPY requirements.txt .
RUN apk --update add --no-cache --virtual .build-dependencies \
    python3-dev \
    build-base \
    wget \
    git \
    libffi-dev \
    openssl-dev \
    && pip install --no-cache-dir --no-binary msgpack -r requirements.txt \
    && apk del .build-dependencies
