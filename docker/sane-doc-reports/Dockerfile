
FROM demisto/python3:3.7.3.260

COPY requirements.txt .

RUN apk add --update --no-cache g++ gcc libxslt-dev freetype-dev jpeg-dev zlib-dev
RUN apk --update add --no-cache --virtual .build-dependencies build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN mkdir sandbox
COPY src sandbox/ 
WORKDIR sandbox
RUN pip install -e .
