# Last modified: 2024-01-09T16:38:56.864163+00:00
FROM demisto/python3:3.10.13.84405

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
