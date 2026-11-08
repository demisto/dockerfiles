# Last modified: 2026-11-08T05:58:46.209600+00:00
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
    && apk del .build-dependencies

