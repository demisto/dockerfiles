FROM demisto/python3:3.12.11.4819260

COPY requirements.txt .

RUN apk --update upgrade && \
    apk del gnutls && \
    apk add --no-cache gnutls && \
    apk add --no-cache \
    libxml2 \
    libxslt \
    tshark \
    libmagic

RUN apk add --no-cache --virtual .build-dependencies \
    python3-dev \
    build-base \
    wget \
    git \
    libxml2-dev \
    libxslt-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-dependencies
