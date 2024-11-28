FROM demisto/python3:3.11.10.116949

ENV DEMISTO_SDK_IGNORE_CONTENT_WARNING true
ENV DEMISTO_SDK_SKIP_LOGGER_SETUP true

COPY requirements.txt .

# Install base dependencies and Python build tools
RUN apk --update add --no-cache --virtual .build-dependencies \
      python3-dev build-base libffi-dev openssl-dev \
  && apk add --no-cache git libstdc++ grep curl \
  && pip install --no-cache-dir poetry \
  && poetry install --no-root \
  && poetry run pre-commit install-hooks \
  && apk del .build-dependencies

RUN poetry run pre-commit install-hooks --verbose


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