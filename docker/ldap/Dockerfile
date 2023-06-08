
FROM demisto/python3:3.10.11.56082

COPY requirements.txt .

# Add tools for troubleshooting
RUN apk --update add --no-cache openssl openldap-clients

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
