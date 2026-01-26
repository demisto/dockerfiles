# Last modified: 2026-01-26T08:48:53.259183+00:00
FROM demisto/python3:3.12.12.6875480


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
