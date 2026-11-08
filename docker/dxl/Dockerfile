# Last modified: 2026-11-08T06:57:06.954910+00:00
FROM demisto/python3:3.12.14.13495286

COPY requirements.txt .
RUN apk --update add --no-cache --virtual .build-dependencies \
    python3-dev \
    build-base \
    wget \
    git \
    libffi-dev \
    openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps "msgpack>=1.2.3" \
    && apk del .build-dependencies
