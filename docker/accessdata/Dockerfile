FROM demisto/python3:3.9.8.24399

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git
RUN pip install --no-cache-dir -r requirements.txt \
RUN apk del .build-dependencies
