
FROM demisto/slackv3:1.0.0.99303

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install slack-sdk==3.27.2 \
  && apk del .build-dependencies 