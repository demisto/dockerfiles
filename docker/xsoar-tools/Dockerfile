ARG CONTENT_DIR=/home/demisto/content

FROM demisto/python3:3.11.10.110725
ENV DEMISTO_SDK_IGNORE_CONTENT_WARNING true
COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev openssl-dev \
  && apk add --no-cache git  \
  && apk add --no-cache libstdc++  \
  && apk add --no-cache --upgrade grep  \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN mkdir -p ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts/CommonServerPython/CommonServerPython.py ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1 ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/tox.ini ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1 ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest/conftest.py ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Config/approved_usecases.json ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Config/approved_tags.json ${CONTENT_DIR}
ADD https://raw.githubusercontent.com/demisto/content/master/Config/approved_categories.json ${CONTENT_DIR}

WORKDIR /home/demisto
