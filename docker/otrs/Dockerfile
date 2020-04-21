FROM demisto/python3:3.8.2.6981

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
&& pip install --no-cache-dir click colorama PyOTRS importlib_metadata \
&& apk del .build-dependencies
