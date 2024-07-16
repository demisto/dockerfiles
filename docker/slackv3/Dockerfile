
FROM demisto/python3:3.11.9.103066

COPY requirements.txt .
RUN sed -i 's/^Options = .*/Options = IgnoreUnexpectedEOF,UnsafeLegacyRenegotiation/' /etc/ssl/openssl.cnf
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
