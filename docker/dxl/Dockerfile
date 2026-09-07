# Last modified: 2026-09-07T12:50:25.931639+00:00
FROM demisto/python3:3.12.14.12826098


COPY requirements.txt .
RUN apk --update add --no-cache --virtual .build-dependencies \
    python3-dev \
    build-base \
    wget \
    git \
    libffi-dev \
    openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps "msgpack>=1.2.1" \
    && apk del .build-dependencies

