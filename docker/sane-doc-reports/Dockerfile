
FROM demisto/python3:3.7.5.3066

COPY requirements.txt .

RUN apk add --update --no-cache g++ gcc libxslt-dev freetype-dev jpeg-dev zlib-dev tzdata
RUN apk --update add --no-cache --virtual .build-dependencies build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
RUN ln -fs /usr/share/zoneinfo/UTC /etc/localtime
RUN mkdir sandbox
COPY src sandbox/ 
WORKDIR sandbox
RUN pip install -e .
