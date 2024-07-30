FROM demisto/python3:3.11.9.104957

COPY requirements.txt .

ARG PYTHON_VERSION_TO_INSTALL=3.11.9

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  mkdir -p /usr/local/src/python && \
  tar -zxf Python-${PYTHON_VERSION_TO_INSTALL}.tgz -C /usr/local/src/python --strip-components=1 && \
  rm -rf Python-${PYTHON_VERSION_TO_INSTALL}.tgz && \
  cd /usr/local/src/python && \
  && ./configure --with-openssl=/usr/local/opt/libressl