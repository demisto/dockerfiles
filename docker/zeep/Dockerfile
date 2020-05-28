FROM demisto/python3:3.7.5.4583

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base libxml2-dev libxslt-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# populate zeep's cache so offline can work too 
ENV ZEEP_STATIC_CACHE=/zeep/static_cache
COPY zeep-add-to-cache.py .
RUN mkdir /zeep/static_cache \
  && chmod 755 /zeep \
  && chmod 755 /zeep/static_cache \
  && python zeep-add-to-cache.py https://www.w3.org/2005/05/xmlmime \
  && python zeep-add-to-cache.py http://www.w3.org/2005/05/xmlmime
