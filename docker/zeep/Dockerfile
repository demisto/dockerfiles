FROM demisto/python3:3.10.11.56082

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libxml2-dev libxslt-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# populate zeep's cache so offline can work too 
ENV ZEEP_STATIC_CACHE_DB=/zeep/static/cache.db
COPY zeep-add-to-cache.py .
RUN mkdir -p /zeep/static \
  && chmod 755 /zeep \
  && chmod 755 /zeep/static \
  && python zeep-add-to-cache.py https://www.w3.org/2005/05/xmlmime \
  && python zeep-add-to-cache.py http://www.w3.org/2005/05/xmlmime
