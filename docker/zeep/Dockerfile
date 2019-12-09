FROM demisto/python3:3.7.5.4583

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base libxml2-dev libxslt-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# populate zeep's cache so offline can work too 
COPY zeep-add-to-cache.py .
RUN python zeep-add-to-cache.py https://www.w3.org/2005/05/xmlmime \
  && python zeep-add-to-cache.py http://www.w3.org/2005/05/xmlmime
