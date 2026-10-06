# Last modified: 2026-09-15T05:03:39.053769+00:00

FROM demisto/python3:3.12.14.13053055

ENV DEMISTO_SDK_IGNORE_CONTENT_WARNING true
ENV DEMISTO_SDK_SKIP_LOGGER_SETUP true

COPY requirements.txt .

RUN apk --update add --no-cache \
  curl=8.22.0-r0 \
  libcurl=8.22.0-r0

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev openssl-dev \
  && apk add --no-cache git  \
  && apk add --no-cache libstdc++  \
  && apk add --no-cache --upgrade grep  \
  && pip install --no-cache-dir "setuptools-scm<10" \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "lxml>=6.1.0" \
  && apk del .build-dependencies

ADD https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts/CommonServerPython/CommonServerPython.py /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1 /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/tox.ini /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1 /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest/conftest.py /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Config/approved_usecases.json /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Config/approved_tags.json /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/Config/approved_categories.json /home/demisto
ADD https://raw.githubusercontent.com/demisto/content/master/.pre-commit-config_template.yaml /home/demisto