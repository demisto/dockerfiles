
FROM demisto/python3:3.10.11.58677
ENV DEMISTO_SDK_IGNORE_CONTENT_WARNING true
COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev openssl-dev wget \
  && apk add --no-cache git  \
  && apk add --no-cache libstdc++  \
  && apk add --no-cache --upgrade grep  \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && wget -P /home/demisto https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts/CommonServerPython/CommonServerPython.py \
  && wget -P /home/demisto https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1 \
  && wget -P /home/demisto https://raw.githubusercontent.com/demisto/content/master/tox.ini \
  && wget -P /home/demisto https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py \
  && wget -P /home/demisto https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1 \
  && wget -P /home/demisto https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest/conftest.py
