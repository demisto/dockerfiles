
FROM demisto/python3:3.10.4.28442

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip list | awk -F' ' {'print $1'} | sed 1,2d | xargs -t -I ARGS sh -c '{ pip show ARGS | grep "License: GPL" && pip uninstall -q -y ARGS; }' && 0 \
  && apk del .build-dependencies
