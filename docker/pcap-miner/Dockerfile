
FROM demisto/python3:3.8.3.8715

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apt-get update && apt-get install -y --no-install-recommends \
  libmagic1 \
&& rm -rf /var/lib/apt/lists/*