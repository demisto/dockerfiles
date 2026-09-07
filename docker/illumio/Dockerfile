# Last modified: 2026-09-07T12:50:20.669612+00:00

FROM demisto/python3:3.12.14.12826098

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
