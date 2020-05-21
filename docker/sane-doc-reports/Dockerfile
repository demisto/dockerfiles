
FROM demisto/python3:3.7.5.4328

COPY requirements.txt .

RUN apk add --no-cache --virtual .build-deps gcc musl-dev \
 && pip install cython \
 && apk del .build-deps
RUN apk add --update --no-cache g++ gcc libxslt-dev freetype-dev jpeg-dev zlib-dev tzdata
RUN apk --update add --no-cache --virtual .build-dependencies build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
RUN ln -fs /usr/share/zoneinfo/UTC /etc/localtime
RUN curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash - \
    sudo apt install -y nodejs \
    npm install svgexport -g

RUN mkdir sandbox
COPY src sandbox/ 
WORKDIR sandbox
RUN pip install -e .
