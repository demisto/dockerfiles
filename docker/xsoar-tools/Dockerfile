
FROM demisto/python3:3.9.1.14969

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
  && apk add --no-cache git  \
  && apk add --no-cache libstdc++  \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && cd /home/demisto \
  && mkdir content \
  && cd content \
  && git init \
  && git remote add origin https://github.com/demisto/content.git \
  && git sparse-checkout init --cone \
  && git sparse-checkout set Packs/Base/Scripts/CommonServerPython Packs/Base/Scripts/CommonServerPowerShell \
  && git pull origin master
