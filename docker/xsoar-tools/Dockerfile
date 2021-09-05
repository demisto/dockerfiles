
FROM demisto/python3:3.9.6.22912

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
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
